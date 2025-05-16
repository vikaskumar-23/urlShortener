#include "httplib.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <random>
#include <chrono>
#include <thread>
#include <regex>
#include <mutex>
#include <sqlite3.h>
using namespace std;
// Global variables with proper scoping
namespace {
    sqlite3 *db = nullptr;
    mutex db_mutex; // Thread safety for database operations
    const size_t CODE_LENGTH = 6; // URL code length
    const string BASE_URL = "http://localhost:8080/u/";
    const int EXPIRY_HOURS = 24; // URL expiry time in hours
}

// Database operations class
class URLDatabase {
public:
    static bool initialize() {
        lock_guard<mutex> lock(db_mutex);
        
        if (sqlite3_open("url_map.db", &db) != SQLITE_OK) {
            cerr << "Cannot open database: " << sqlite3_errmsg(db) << endl;
            return false;
        }
        
        // Create table with expiry timestamp
        const char *create_table_sql = 
            "CREATE TABLE IF NOT EXISTS url_map ("
            "short_code TEXT PRIMARY KEY,"
            "original_url TEXT NOT NULL,"
            "created_at INTEGER NOT NULL"
            ");";
        
        char *err_msg = nullptr;
        if (sqlite3_exec(db, create_table_sql, 0, 0, &err_msg) != SQLITE_OK) {
            cerr << "SQL error: " << err_msg << endl;
            sqlite3_free(err_msg);
            return false;
        }
        
        // Create indexes for better query performance
        const char *create_index_sql = 
            "CREATE INDEX IF NOT EXISTS idx_created_at ON url_map(created_at);";
        
        if (sqlite3_exec(db, create_index_sql, 0, 0, &err_msg) != SQLITE_OK) {
            cerr << "SQL index error: " << err_msg << endl;
            sqlite3_free(err_msg);
            return false;
        }
        
        // Start cleanup task in a separate thread
        thread cleanup_thread([]() {
            while (true) {
                cleanupExpiredURLs();
                // Run cleanup every hour
                this_thread::sleep_for(chrono::hours(1));
            }
        });
        cleanup_thread.detach();
        
        return true;
    }
    
    static void close() {
        lock_guard<mutex> lock(db_mutex);
        if (db) {
            sqlite3_close(db);
            db = nullptr;
        }
    }
    
    static bool storeURL(const string &code, const string &url) {
        lock_guard<mutex> lock(db_mutex);
        
        // Get current timestamp
        auto now = chrono::system_clock::now();
        int64_t timestamp = chrono::duration_cast<chrono::seconds>(
            now.time_since_epoch()).count();
        
        const char *insert_sql = 
            "INSERT OR REPLACE INTO url_map (short_code, original_url, created_at) "
            "VALUES (?, ?, ?);";
        
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << endl;
            return false;
        }
        
        sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, url.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, timestamp);
        
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        return (rc == SQLITE_DONE);
    }
    
    static bool getOriginalURL(const string &code, string &url) {
        lock_guard<mutex> lock(db_mutex);
        
        // Get current timestamp
        auto now = chrono::system_clock::now();
        int64_t current_timestamp = chrono::duration_cast<chrono::seconds>(
            now.time_since_epoch()).count();
        int64_t expiry_seconds = EXPIRY_HOURS * 3600;
        
        const char *select_sql = 
            "SELECT original_url, created_at FROM url_map WHERE short_code = ?;";
        
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << endl;
            return false;
        }
        
        sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int64_t created_at = sqlite3_column_int64(stmt, 1);
            sqlite3_finalize(stmt);
            
            // Check if URL has expired
            if (current_timestamp - created_at > expiry_seconds) {
                // URL has expired, remove it
                const char *delete_sql = "DELETE FROM url_map WHERE short_code = ?;";
                rc = sqlite3_prepare_v2(db, delete_sql, -1, &stmt, nullptr);
                
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                return false; // URL has expired
            }
            
            return true;
        }
        
        sqlite3_finalize(stmt);
        return false;
    }
    
    static void cleanupExpiredURLs() {
        lock_guard<mutex> lock(db_mutex);
        
        // Calculate expiry timestamp
        auto now = chrono::system_clock::now();
        int64_t current_timestamp = chrono::duration_cast<chrono::seconds>(
            now.time_since_epoch()).count();
        int64_t expiry_timestamp = current_timestamp - (EXPIRY_HOURS * 3600);
        
        const char *delete_sql = "DELETE FROM url_map WHERE created_at < ?;";
        sqlite3_stmt *stmt;
        
        if (sqlite3_prepare_v2(db, delete_sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, expiry_timestamp);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            // Output cleanup stats
            int changes = sqlite3_changes(db);
            if (changes > 0) {
                cout << "Cleaned up " << changes << " expired URLs" << endl;
            }
        }
    }
};

// URL validation function
bool isValidURL(const string &url) {
    // Basic URL validation regex
    regex url_regex(
        R"(^(https?|ftp):\/\/)"  // protocol
        R"(([^\s:@/]+:[^\s:@/]+@)?)"  // optional username:password
        R"(([^\s:\.]+\.)+[^\s:\.]{2,})"  // domain
        R"((\:[0-9]+)?)"  // optional port
        R"((\/[^\s]*)?$)",  // optional path
        regex::extended
    );
    
    return regex_match(url, url_regex) && url.length() < 2048;
}

// Generate a random short code
string generateShortCode() {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    string result;
    result.reserve(CODE_LENGTH);
    
    static random_device rd;
    static mt19937 gen(rd());
    static uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    
    for (size_t i = 0; i < CODE_LENGTH; ++i) {
        result += charset[dist(gen)];
    }
    
    return result;
}

// HTTP response helpers
namespace {
    void sendJsonResponse(httplib::Response &res, int status, const string &message, 
                          const string &shortUrl = "") {
        res.status = status;
        res.set_header("Content-Type", "application/json");
        
        stringstream json;
        json << "{";
        
        if (!shortUrl.empty()) {
            json << "\"shortUrl\": \"" << shortUrl << "\",";
        }
        
        json << "\"status\": " << (status == 200 ? "\"success\"" : "\"error\"")
             << ", \"message\": \"" << message << "\"}";
        
        res.set_content(json.str(), "application/json");
    }
}

// Main function
int main() {
    // Initialize database
    if (!URLDatabase::initialize()) {
        cerr << "Failed to initialize database, exiting." << endl;
        return 1;
    }
    
    httplib::Server svr;
    
    // Serve the main page
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        ifstream file("index.html");
        if (!file) {
            res.status = 500;
            res.set_content("Could not load index.html", "text/plain");
            return;
        }
        
        stringstream buffer;
        buffer << file.rdbuf();
        res.set_content(buffer.str(), "text/html");
    });
    
    // Handle URL shortening requests
    svr.Post("/shorten", [](const httplib::Request &req, httplib::Response &res) {
        // Check if URL parameter exists
        if (!req.has_param("url")) {
            sendJsonResponse(res, 400, "Missing URL parameter");
            return;
        }
        
        string url = req.get_param_value("url");
        
        // Validate URL
        if (!isValidURL(url)) {
            sendJsonResponse(res, 400, "Invalid URL format");
            return;
        }
        
        // Try to generate a unique code (with collision handling)
        string code;
        string dummy;
        bool success = false;
        
        // Try up to 5 times in case of collision
        for (int attempts = 0; attempts < 5; attempts++) {
            code = generateShortCode();
            
            // Check if code already exists
            if (!URLDatabase::getOriginalURL(code, dummy)) {
                // Store the new URL mapping
                if (URLDatabase::storeURL(code, url)) {
                    success = true;
                    break;
                }
            }
        }
        
        if (success) {
            string shortUrl = BASE_URL + code;
            sendJsonResponse(res, 200, "URL shortened successfully", shortUrl);
        } else {
            sendJsonResponse(res, 500, "Failed to create short URL, please try again");
        }
    });
    
    // Handle URL redirection
    svr.Get(R"(/u/(\w+))", [](const httplib::Request &req, httplib::Response &res) {
        string code = req.matches[1];
        string url;
        
        if (URLDatabase::getOriginalURL(code, url)) {
            res.set_redirect(url);
        } else {
            res.status = 404;
            res.set_content("URL not found or has expired!", "text/plain");
        }
    });
    
    // Stats endpoint (optional)
    svr.Get("/stats", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("URL Shortener Statistics", "text/plain");
    });
    
    // Start the server
    cout << "Server started at http://localhost:8080" << endl;
    cout << "URLs will expire after " << EXPIRY_HOURS << " hours" << endl;
    
    svr.listen("localhost", 8080);
    
    // Clean up
    URLDatabase::close();
    return 0;
}