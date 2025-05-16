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
#include <atomic>
#include <map>
#include <vector>
#include <unordered_map>
#include <queue>
#include <condition_variable>
#include <signal.h>
#include "json.hpp"


// For JSON operations
using json = nlohmann::json;

// Configuration structure
struct Config {
    std::string db_path = "url_map.db";
    std::string base_url = "http://localhost:8080/u/";
    int expiry_hours = 24;
    size_t code_length = 6;
    int cleanup_interval_minutes = 60;
    int connection_pool_size = 5;
    int max_requests_per_minute = 60;
    bool enable_custom_slugs = true;
    std::string log_level = "info";
    std::string admin_token = "admin_secret_token";
};

// Global configuration
Config config;

// Logger with different levels
class Logger {
public:
    enum Level {
        DEBUG,
        INFO,
        WARNING,
        ERR,
        CRITICAL
    };

    static void setLevel(const std::string& level) {
        if (level == "debug") current_level = DEBUG;
        else if (level == "info") current_level = INFO;
        else if (level == "warning") current_level = WARNING;
        else if (level == "error") current_level = ERR;
        else if (level == "critical") current_level = CRITICAL;
    }

    template<typename... Args>
    static void debug(const char* format, Args... args) {
        if (current_level <= DEBUG) log(DEBUG, format, args...);
    }

    template<typename... Args>
    static void info(const char* format, Args... args) {
        if (current_level <= INFO) log(INFO, format, args...);
    }

    template<typename... Args>
    static void warning(const char* format, Args... args) {
        if (current_level <= WARNING) log(WARNING, format, args...);
    }

    template<typename... Args>
    static void error(const char* format, Args... args) {
        if (current_level <= ERR) log(ERR, format, args...);
    }

    template<typename... Args>
    static void critical(const char* format, Args... args) {
        if (current_level <= CRITICAL) log(CRITICAL, format, args...);
    }

private:
    static Level current_level;

    template<typename... Args>
    static void log(Level level, const char* format, Args... args) {
        char buffer[1024];
        snprintf(buffer, sizeof(buffer), format, args...);
        
        std::string level_str;
        
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf;
        
#ifdef _WIN32
        localtime_s(&tm_buf, &time);
#else
        localtime_r(&time, &tm_buf);
#endif
        
        char time_str[32];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
        
        std::lock_guard<std::mutex> lock(log_mutex);
        std::cout << "[" << time_str << "] [" << level_str << "] " << buffer << std::endl;
    }

    static std::mutex log_mutex;
};

std::mutex Logger::log_mutex;
Logger::Level Logger::current_level = Logger::INFO;

// Server control
std::atomic<bool> running{true};

// Rate limiting implementation
class RateLimiter {
public:
    bool checkLimit(const std::string& ip_address) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto& bucket = ip_buckets_[ip_address];
        
        // Clean old timestamps
        while (!bucket.empty() && 
               std::chrono::duration_cast<std::chrono::minutes>(now - bucket.front()).count() >= 1) {
            bucket.pop();
        }
        
        // Check if under limit
        if (bucket.size() < config.max_requests_per_minute) {
            bucket.push(now);
            return true;
        }
        
        return false;
    }
    
private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::queue<std::chrono::steady_clock::time_point>> ip_buckets_;
};

// Connection pooling
class DBConnectionPool {
public:
    DBConnectionPool(int pool_size) : pool_size_(pool_size) {}
    
    bool initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (int i = 0; i < pool_size_; ++i) {
            sqlite3* db = nullptr;
            if (sqlite3_open(config.db_path.c_str(), &db) != SQLITE_OK) {
                Logger::error("Cannot open database: %s", sqlite3_errmsg(db));
                // Clean up previously opened connections
                for (auto* conn : available_) {
                    sqlite3_close(conn);
                }
                available_.clear();
                return false;
            }
            
            // Enable foreign keys
            char* err_msg = nullptr;
            if (sqlite3_exec(db, "PRAGMA foreign_keys = ON;", 0, 0, &err_msg) != SQLITE_OK) {
                Logger::error("Failed to enable foreign keys: %s", err_msg);
                sqlite3_free(err_msg);
            }
            
            available_.push_back(db);
        }
        
        return true;
    }
    
    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (auto* db : available_) {
            sqlite3_close(db);
        }
        available_.clear();
        
        for (auto* db : in_use_) {
            sqlite3_close(db);
        }
        in_use_.clear();
    }
    
    sqlite3* getConnection() {
        std::unique_lock<std::mutex> lock(mutex_);
        
        while (available_.empty() && running) {
            // Wait for a connection to become available
            cv_.wait(lock);
        }
        
        if (!running) {
            return nullptr;
        }
        
        sqlite3* db = available_.back();
        available_.pop_back();
        in_use_.push_back(db);
        
        return db;
    }
    
    void releaseConnection(sqlite3* db) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = std::find(in_use_.begin(), in_use_.end(), db);
        if (it != in_use_.end()) {
            in_use_.erase(it);
            available_.push_back(db);
            cv_.notify_one();
        }
    }
    
private:
    int pool_size_;
    std::vector<sqlite3*> available_;
    std::vector<sqlite3*> in_use_;
    std::mutex mutex_;
    std::condition_variable cv_;
};

// URL validator using regex
class URLValidator {
public:
    static bool validateURL(const std::string& url) {
        // Basic validation to prevent the most obvious malicious URLs
        // This is not exhaustive but catches obvious issues
        
        // Reject empty URLs
        if (url.empty()) {
            return false;
        }
        
        // Check for common protocols
        if (url.substr(0, 7) != "http://" && 
            url.substr(0, 8) != "https://" && 
            url.substr(0, 6) != "ftp://") {
            return false;
        }
        
        // Basic regex check for URL structure
        static const std::regex url_regex(
            R"(^(https?|ftp)://([^\s/$.?#].[^\s]*)$)",
            std::regex::icase
        );
        
        return std::regex_match(url, url_regex);
    }
    
    static std::string sanitizeInput(const std::string& input) {
        // Remove any HTML/script tags
        std::string result = input;
        static const std::regex script_regex("<script[^>]*>.*?</script>", 
                                            std::regex::icase | std::regex::extended);
        result = std::regex_replace(result, script_regex, "");
        
        // Remove other potentially harmful tags
        static const std::regex tag_regex("<[^>]*>", 
                                         std::regex::icase | std::regex::extended);
        result = std::regex_replace(result, tag_regex, "");
        
        return result;
    }
    
    static bool validateCustomSlug(const std::string& slug) {
        // Only allow alphanumeric and a few special characters
        static const std::regex slug_regex("^[a-zA-Z0-9_-]{4,16}$");
        return std::regex_match(slug, slug_regex);
    }
};

// Database operations class with connection pooling
class URLDatabase {
public:
    static bool initialize(DBConnectionPool& pool) {
        sqlite3* db = pool.getConnection();
        if (!db) {
            return false;
        }
        
        // Create main table with additional fields for analytics
        const char* create_url_table_sql = 
            "CREATE TABLE IF NOT EXISTS url_map ("
            "short_code TEXT PRIMARY KEY,"
            "original_url TEXT NOT NULL,"
            "created_at INTEGER NOT NULL,"
            "is_custom INTEGER DEFAULT 0,"
            "ip_address TEXT,"
            "click_count INTEGER DEFAULT 0,"
            "user_id INTEGER"
            ");";
        
        // Create users table
        const char* create_users_table_sql =
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "username TEXT UNIQUE NOT NULL,"
            "password_hash TEXT NOT NULL,"
            "email TEXT UNIQUE,"
            "created_at INTEGER NOT NULL"
            ");";
        
        // Create click analytics table
        const char* create_analytics_table_sql =
            "CREATE TABLE IF NOT EXISTS clicks ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "short_code TEXT NOT NULL,"
            "clicked_at INTEGER NOT NULL,"
            "ip_address TEXT,"
            "user_agent TEXT,"
            "referrer TEXT,"
            "FOREIGN KEY (short_code) REFERENCES url_map(short_code) ON DELETE CASCADE"
            ");";
        
        // Execute all creation statements
        char* err_msg = nullptr;
        bool success = true;
        
        if (sqlite3_exec(db, create_url_table_sql, 0, 0, &err_msg) != SQLITE_OK) {
            Logger::error("SQL error: %s", err_msg);
            sqlite3_free(err_msg);
            success = false;
        }
        
        if (success && sqlite3_exec(db, create_users_table_sql, 0, 0, &err_msg) != SQLITE_OK) {
            Logger::error("SQL error: %s", err_msg);
            sqlite3_free(err_msg);
            success = false;
        }
        
        if (success && sqlite3_exec(db, create_analytics_table_sql, 0, 0, &err_msg) != SQLITE_OK) {
            Logger::error("SQL error: %s", err_msg);
            sqlite3_free(err_msg);
            success = false;
        }
        
        // Create indexes for better query performance
        const char* create_indexes_sql[] = {
            "CREATE INDEX IF NOT EXISTS idx_created_at ON url_map(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_click_count ON url_map(click_count);",
            "CREATE INDEX IF NOT EXISTS idx_user_id ON url_map(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_clicks_short_code ON clicks(short_code);",
            "CREATE INDEX IF NOT EXISTS idx_clicks_clicked_at ON clicks(clicked_at);"
        };
        
        for (const auto& index_sql : create_indexes_sql) {
            if (success && sqlite3_exec(db, index_sql, 0, 0, &err_msg) != SQLITE_OK) {
                Logger::error("SQL index error: %s", err_msg);
                sqlite3_free(err_msg);
                success = false;
                break;
            }
        }
        
        pool.releaseConnection(db);
        return success;
    }
    
    static bool storeURL(DBConnectionPool& pool, const std::string& code, 
                        const std::string& url, const std::string& ip_address,
                        bool is_custom = false, int user_id = -1) {
        sqlite3* db = pool.getConnection();
        if (!db) return false;
        
        // Get current timestamp
        auto now = std::chrono::system_clock::now();
        int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        
        const char* insert_sql = 
            "INSERT OR REPLACE INTO url_map "
            "(short_code, original_url, created_at, is_custom, ip_address, user_id) "
            "VALUES (?, ?, ?, ?, ?, ?);";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            Logger::error("Failed to prepare statement: %s", sqlite3_errmsg(db));
            pool.releaseConnection(db);
            return false;
        }
        
        sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, url.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, timestamp);
        sqlite3_bind_int(stmt, 4, is_custom ? 1 : 0);
        sqlite3_bind_text(stmt, 5, ip_address.c_str(), -1, SQLITE_TRANSIENT);
        
        if (user_id >= 0) {
            sqlite3_bind_int(stmt, 6, user_id);
        } else {
            sqlite3_bind_null(stmt, 6);
        }
        
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        pool.releaseConnection(db);
        return (rc == SQLITE_DONE);
    }
    
    static bool getOriginalURL(DBConnectionPool& pool, const std::string& code, 
                              std::string& url, bool increment_count = true) {
        sqlite3* db = pool.getConnection();
        if (!db) return false;
        
        // Get current timestamp
        auto now = std::chrono::system_clock::now();
        int64_t current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        int64_t expiry_seconds = config.expiry_hours * 3600;
        
        const char* select_sql = 
            "SELECT original_url, created_at FROM url_map WHERE short_code = ?;";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            Logger::error("Failed to prepare statement: %s", sqlite3_errmsg(db));
            pool.releaseConnection(db);
            return false;
        }
        
        sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
        
        bool result = false;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int64_t created_at = sqlite3_column_int64(stmt, 1);
            sqlite3_finalize(stmt);
            
            // Check if URL has expired
            if (current_timestamp - created_at > expiry_seconds) {
                // URL has expired, remove it
                const char* delete_sql = "DELETE FROM url_map WHERE short_code = ?;";
                rc = sqlite3_prepare_v2(db, delete_sql, -1, &stmt, nullptr);
                
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                
                Logger::info("URL with code %s has expired and been removed", code.c_str());
                result = false;
            } else {
                result = true;
                
                // Increment click count if requested
                if (increment_count) {
                    const char* update_sql = 
                        "UPDATE url_map SET click_count = click_count + 1 WHERE short_code = ?;";
                    rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, nullptr);
                    
                    if (rc == SQLITE_OK) {
                        sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                }
            }
        } else {
            sqlite3_finalize(stmt);
        }
        
        pool.releaseConnection(db);
        return result;
    }
    
    static bool recordClickAnalytics(DBConnectionPool& pool, const std::string& code,
                                    const std::string& ip_address, const std::string& user_agent,
                                    const std::string& referrer) {
        sqlite3* db = pool.getConnection();
        if (!db) return false;
        
        // Get current timestamp
        auto now = std::chrono::system_clock::now();
        int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        
        const char* insert_sql = 
            "INSERT INTO clicks (short_code, clicked_at, ip_address, user_agent, referrer) "
            "VALUES (?, ?, ?, ?, ?);";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            Logger::error("Failed to prepare analytics statement: %s", sqlite3_errmsg(db));
            pool.releaseConnection(db);
            return false;
        }
        
        sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, timestamp);
        sqlite3_bind_text(stmt, 3, ip_address.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, user_agent.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, referrer.c_str(), -1, SQLITE_TRANSIENT);
        
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        pool.releaseConnection(db);
        return (rc == SQLITE_DONE);
    }
    
    static void cleanupExpiredURLs(DBConnectionPool& pool) {
        sqlite3* db = pool.getConnection();
        if (!db) return;
        
        // Calculate expiry timestamp
        auto now = std::chrono::system_clock::now();
        int64_t current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        int64_t expiry_timestamp = current_timestamp - (config.expiry_hours * 3600);
        
        const char* delete_sql = "DELETE FROM url_map WHERE created_at < ?;";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db, delete_sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, expiry_timestamp);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            
            // Output cleanup stats
            int changes = sqlite3_changes(db);
            if (changes > 0) {
                Logger::info("Cleaned up %d expired URLs", changes);
            }
        }
        
        pool.releaseConnection(db);
    }
    
    static json getURLStats(DBConnectionPool& pool, const std::string& code) {
        sqlite3* db = pool.getConnection();
        if (!db) return json::object();
        
        json result = {
            {"success", false},
            {"message", "URL not found"}
        };
        
        // Get URL details
        const char* url_sql = 
            "SELECT original_url, created_at, click_count, is_custom "
            "FROM url_map WHERE short_code = ?;";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, url_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            Logger::error("Failed to prepare stats statement: %s", sqlite3_errmsg(db));
            pool.releaseConnection(db);
            return result;
        }
        
        sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string original_url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int64_t created_at = sqlite3_column_int64(stmt, 1);
            int click_count = sqlite3_column_int(stmt, 2);
            bool is_custom = sqlite3_column_int(stmt, 3) > 0;
            
            result["success"] = true;
            result["message"] = "Stats retrieved successfully";
            result["url"] = {
                {"short_code", code},
                {"original_url", original_url},
                {"short_url", config.base_url + code},
                {"created_at", created_at},
                {"click_count", click_count},
                {"is_custom", is_custom}
            };
            
            // Convert timestamp to human-readable format
            auto time_point = std::chrono::system_clock::time_point(
                std::chrono::seconds(created_at));
            auto time = std::chrono::system_clock::to_time_t(time_point);
            char time_str[32];
            
#ifdef _WIN32
            std::tm tm_buf;
            localtime_s(&tm_buf, &time);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
#else
            std::tm tm_buf;
            localtime_r(&time, &tm_buf);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
#endif
            
            result["url"]["created_at_str"] = time_str;
            
            // Get expiry time
            auto expiry_time = time + (config.expiry_hours * 3600);
            
#ifdef _WIN32
            localtime_s(&tm_buf, &expiry_time);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
#else
            localtime_r(&expiry_time, &tm_buf);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
#endif
            
            result["url"]["expires_at_str"] = time_str;
            
            // Get recent clicks (last 10)
            sqlite3_finalize(stmt);
            
            const char* clicks_sql = 
                "SELECT clicked_at, ip_address, user_agent, referrer "
                "FROM clicks WHERE short_code = ? "
                "ORDER BY clicked_at DESC LIMIT 10;";
            
            rc = sqlite3_prepare_v2(db, clicks_sql, -1, &stmt, nullptr);
            
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                
                json clicks = json::array();
                
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    int64_t clicked_at = sqlite3_column_int64(stmt, 0);
                    
                    std::string ip = "";
                    if (sqlite3_column_text(stmt, 1) != nullptr) {
                        ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    }
                    
                    std::string agent = "";
                    if (sqlite3_column_text(stmt, 2) != nullptr) {
                        agent = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                    }
                    
                    std::string ref = "";
                    if (sqlite3_column_text(stmt, 3) != nullptr) {
                        ref = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
                    }
                    
                    // Convert timestamp to human-readable format
                    auto click_time_point = std::chrono::system_clock::time_point(
                        std::chrono::seconds(clicked_at));
                    auto click_time = std::chrono::system_clock::to_time_t(click_time_point);
                    
#ifdef _WIN32
                    localtime_s(&tm_buf, &click_time);
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
#else
                    localtime_r(&click_time, &tm_buf);
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
#endif
                    
                    clicks.push_back({
                        {"clicked_at", clicked_at},
                        {"clicked_at_str", time_str},
                        {"ip_address", ip},
                        {"user_agent", agent},
                        {"referrer", ref}
                    });
                }
                
                result["clicks"] = clicks;
            }
        }
        
        sqlite3_finalize(stmt);
        pool.releaseConnection(db);
        return result;
    }
    
    static bool checkCodeExists(DBConnectionPool& pool, const std::string& code) {
        sqlite3* db = pool.getConnection();
        if (!db) return true; // Safer to return true if we can't check
        
        const char* select_sql = "SELECT 1 FROM url_map WHERE short_code = ?;";
        sqlite3_stmt* stmt;
        
        int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            Logger::error("Failed to prepare check code statement: %s", sqlite3_errmsg(db));
            pool.releaseConnection(db);
            return true;
        }
        
        sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        bool exists = (rc == SQLITE_ROW);
        
        sqlite3_finalize(stmt);
        pool.releaseConnection(db);
        return exists;
    }
    
    static json getAllUserURLs(DBConnectionPool& pool, int user_id, int limit = 20, int offset = 0) {
        sqlite3* db = pool.getConnection();
        if (!db) return json::object();
        
        json result = {
            {"success", false},
            {"message", "Failed to retrieve URLs"},
            {"urls", json::array()}
        };
        
        const char* select_sql = 
            "SELECT short_code, original_url, created_at, click_count, is_custom "
            "FROM url_map WHERE user_id = ? "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?;";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            Logger::error("Failed to prepare user URLs statement: %s", sqlite3_errmsg(db));
            pool.releaseConnection(db);
            return result;
        }
        
        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, limit);
        sqlite3_bind_int(stmt, 3, offset);
        
        json urls = json::array();
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string code = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string original_url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            int64_t created_at = sqlite3_column_int64(stmt, 2);
            int click_count = sqlite3_column_int(stmt, 3);
            bool is_custom = sqlite3_column_int(stmt, 4) > 0;
            
            // Convert timestamp to human-readable format
            auto time_point = std::chrono::system_clock::time_point(
                std::chrono::seconds(created_at));
            auto time = std::chrono::system_clock::to_time_t(time_point);
            char time_str[32];
            
#ifdef _WIN32
            std::tm tm_buf;
            localtime_s(&tm_buf, &time);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
#else
            std::tm tm_buf;
            localtime_r(&time, &tm_buf);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
#endif
            
            urls.push_back({
                {"short_code", code},
                {"original_url", original_url},
                {"short_url", config.base_url + code},
                {"created_at", created_at},
                {"created_at_str", time_str},
                {"click_count", click_count},
                {"is_custom", is_custom}
            });
        }
        
        sqlite3_finalize(stmt);
        
        // Get total count
        const char* count_sql = "SELECT COUNT(*) FROM url_map WHERE user_id = ?;";
        rc = sqlite3_prepare_v2(db, count_sql, -1, &stmt, nullptr);
        
        int total_count = 0;
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, user_id);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                total_count = sqlite3_column_int(stmt, 0);
            }
        }
        
        sqlite3_finalize(stmt);
        pool.releaseConnection(db);
        
        result["success"] = true;
        result["message"] = "URLs retrieved successfully";
        result["urls"] = urls;
        result["total"] = total_count;
        result["limit"] = limit;
        result["offset"] = offset;
        
        return result;
    }
};

// Generate a random short code
std::string generateShortCode() {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    std::string result;
    result.reserve(config.code_length);
    
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    
    for (size_t i = 0; i < config.code_length; ++i) {
        result += charset[dist(gen)];
    }
    
    return result;
}

// QR Code generator helper
std::string generateQRCodeSVG(const std::string& url) {
    // This is a placeholder for QR code generation
    // In a real implementation, you would use a library like libqrencode
    std::string svg = "<svg width=\"200\" height=\"200\" xmlns=\"http://www.w3.org/2000/svg\">";
    svg += "<rect width=\"200\" height=\"200\" fill=\"white\"/>";
    svg += "<text x=\"20\" y=\"100\" font-family=\"Arial\" font-size=\"12\">QR Code for: " + url + "</text>";
    svg += "</svg>";
    return svg;
}

// HTTP response helpers
void sendJsonResponse(httplib::Response &res, int status, const json& data) {
    res.status = status;
    res.set_header("Content-Type", "application/json");
    
    // Set CORS headers
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type");
    
    res.set_content(data.dump(2), "application/json");
}

// Load configuration from file
bool loadConfig() {
    std::ifstream config_file("config.json");
    if (!config_file.is_open()) {
        Logger::info("No config file found, using defaults");
        return true; // Use defaults
    }
    
    try {
        json j;
        config_file >> j;
        
        if (j.contains("db_path")) config.db_path = j["db_path"];
        if (j.contains("base_url")) config.base_url = j["base_url"];
        if (j.contains("expiry_hours")) config.expiry_hours = j["expiry_hours"];
        if (j.contains("code_length")) config.code_length = j["code_length"];
        if (j.contains("cleanup_interval_minutes")) config.cleanup_interval_minutes = j["cleanup_interval_minutes"];
        if (j.contains("connection_pool_size")) config.connection_pool_size = j["connection_pool_size"];
        if (j.contains("max_requests_per_minute")) config.max_requests_per_minute = j["max_requests_per_minute"];
        if (j.contains("enable_custom_slugs")) config.enable_custom_slugs = j["enable_custom_slugs"];
        if (j.contains("log_level")) config.log_level = j["log_level"];
        if (j.contains("admin_token")) config.admin_token = j["admin_token"];
        
        Logger::setLevel(config.log_level);
        Logger::info("Configuration loaded from config.json");
        return true;
    }
    catch (const std::exception& e) {
        Logger::error("Error parsing config file: %s", e.what());
        return false;
    }
}

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    Logger::info("Received signal %d, shutting down...", signal);
    running = false;
}

// Main function
int main() {
    // Windows-specific initialization for sockets
    #ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }
    #endif
    
    // Set up signal handling for graceful shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Load configuration
    if (!loadConfig()) {
        return 1;
    }
    
    // Initialize connection pool
    Logger::info("Initializing with a pool of %d database connections", config.connection_pool_size);
    DBConnectionPool pool(config.connection_pool_size);
    if (!pool.initialize()) {
        Logger::critical("Failed to initialize connection pool, exiting");
        return 1;
    }
    
    // Initialize database schema
    if (!URLDatabase::initialize(pool)) {
        Logger::critical("Failed to initialize database schema, exiting");
        pool.close();
        return 1;
    }
    
    // Create rate limiter
    RateLimiter rate_limiter;
    
    // Start cleanup thread
    std::thread cleanup_thread([&pool]() {
        while (running) {
            URLDatabase::cleanupExpiredURLs(pool);
            // Sleep for the configured interval
            std::this_thread::sleep_for(std::chrono::minutes(config.cleanup_interval_minutes));
        }
    });
    
    httplib::Server svr;
    
    // Handle CORS preflight requests
    svr.Options("/(.*)", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.status = 204; // No content
    });
    
    // Middleware for rate limiting
    svr.set_pre_routing_handler([&rate_limiter](const httplib::Request& req, httplib::Response& res) {
        // Skip rate limiting for static assets
        if (req.path.rfind("/assets/", 0) == 0 || req.path == "/favicon.ico") {
            return httplib::Server::HandlerResponse::Unhandled;
        }
        
        std::string ip_address = req.remote_addr;
        
        // Check if request is within limits
        if (!rate_limiter.checkLimit(ip_address)) {
            json error = {
                {"status", "error"},
                {"message", "Rate limit exceeded. Please try again later."}
            };
            sendJsonResponse(res, 429, error);
            return httplib::Server::HandlerResponse::Handled;
        }
        
        return httplib::Server::HandlerResponse::Unhandled;
    });
    
    // Serve the main page
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        // Use a more Windows-friendly file path handling
        std::ifstream file("index.html");
        if (!file) {
            // Try relative path from executable location
            file.open("./index.html");
        }
        
        if (!file) {
            res.status = 500;
            res.set_content("Could not load index.html", "text/plain");
            return;
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        res.set_content(buffer.str(), "text/html");
    });
    
    // Static assets handler
    svr.Get("/assets/(.*)", [](const httplib::Request& req, httplib::Response& res) {
        std::string file_path = "assets/" + std::string(req.matches[1]);
        std::ifstream file(file_path, std::ios::binary);
        
        if (!file) {
            res.status = 404;
            return;
        }
        
        std::string extension = file_path.substr(file_path.find_last_of(".") + 1);
        std::string content_type;
        
        if (extension == "css") content_type = "text/css";
        else if (extension == "js") content_type = "application/javascript";
        else if (extension == "png") content_type = "image/png";
        else if (extension == "jpg" || extension == "jpeg") content_type = "image/jpeg";
        else if (extension == "svg") content_type = "image/svg+xml";
        else content_type = "application/octet-stream";
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        res.set_content(buffer.str(), content_type);
    });
    
    // Handle URL shortening requests
    svr.Post("/shorten", [&pool, &rate_limiter](const httplib::Request &req, httplib::Response &res) {
        std::string ip_address = req.remote_addr;
        
        // Check parameters
        if (!req.has_param("url")) {
            json error = {
                {"status", "error"},
                {"message", "Missing URL parameter"}
            };
            sendJsonResponse(res, 400, error);
            return;
        }
        
        std::string url = req.get_param_value("url");
        url = URLValidator::sanitizeInput(url);
        
        // Basic URL validation
        if (!URLValidator::validateURL(url)) {
            json error = {
                {"status", "error"},
                {"message", "Invalid URL format. Please enter a valid URL."}
            };
            sendJsonResponse(res, 400, error);
            return;
        }
        
        // Handle custom slug if provided and enabled
        std::string code;
        bool is_custom = false;
        
        if (config.enable_custom_slugs && req.has_param("custom_slug")) {
            std::string custom_slug = req.get_param_value("custom_slug");
            custom_slug = URLValidator::sanitizeInput(custom_slug);
            
            if (!custom_slug.empty()) {
                if (!URLValidator::validateCustomSlug(custom_slug)) {
                    json error = {
                        {"status", "error"},
                        {"message", "Custom slug must be 4-16 characters and can only contain letters, numbers, underscore and hyphen."}
                    };
                    sendJsonResponse(res, 400, error);
                    return;
                }
                
                // Check if custom slug already exists
                if (URLDatabase::checkCodeExists(pool, custom_slug)) {
                    json error = {
                        {"status", "error"},
                        {"message", "Custom slug already in use. Please choose another."}
                    };
                    sendJsonResponse(res, 409, error);
                    return;
                }
                
                code = custom_slug;
                is_custom = true;
            }
        }
        
        // If no custom slug or it was empty, generate a random code
        if (code.empty()) {
            // Try to generate a unique code (with collision handling)
            bool success = false;
            
            // Try up to 5 times in case of collision
            for (int attempts = 0; attempts < 5; attempts++) {
                code = generateShortCode();
                
                // Check if code already exists
                if (!URLDatabase::checkCodeExists(pool, code)) {
                    success = true;
                    break;
                }
            }
            
            if (!success) {
                json error = {
                    {"status", "error"},
                    {"message", "Failed to create unique short URL, please try again"}
                };
                sendJsonResponse(res, 500, error);
                return;
            }
        }
        
        // Get user ID if token provided (user auth would be more robust in practice)
        int user_id = -1;
        if (req.has_param("token")) {
            // Simplified auth - would be more robust in production
            // Just using the admin token for demo purposes
            std::string token = req.get_param_value("token");
            if (token == config.admin_token) {
                user_id = 1; // Admin user
            }
        }
        
        // Store the URL
        if (URLDatabase::storeURL(pool, code, url, ip_address, is_custom, user_id)) {
            std::string short_url = config.base_url + code;
            
            json response = {
                {"status", "success"},
                {"message", "URL shortened successfully"},
                {"shortUrl", short_url},
                {"shortCode", code},
                {"originalUrl", url},
                {"isCustom", is_custom},
                {"expiresAfterHours", config.expiry_hours}
            };
            
            sendJsonResponse(res, 200, response);
        } else {
            json error = {
                {"status", "error"},
                {"message", "Database error. Failed to create short URL."}
            };
            sendJsonResponse(res, 500, error);
        }
    });
    
    // Handle URL redirection with analytics
    svr.Get(R"(/u/(\w+))", [&pool](const httplib::Request &req, httplib::Response &res) {
        std::string code = req.matches[1];
        std::string url;
        
        if (URLDatabase::getOriginalURL(pool, code, url, true)) {
            // Record analytics
            std::string ip = req.remote_addr;
            std::string user_agent = req.has_header("User-Agent") ? 
                                    req.get_header_value("User-Agent") : "";
            std::string referrer = req.has_header("Referer") ? 
                                  req.get_header_value("Referer") : "";
            
            // Log analytics asynchronously to not delay the redirect
            std::thread([&pool, code, ip, user_agent, referrer]() {
                URLDatabase::recordClickAnalytics(pool, code, ip, user_agent, referrer);
            }).detach();
            
            // Set cache control to prevent browsers from caching the redirect
            res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
            res.set_header("Pragma", "no-cache");
            res.set_header("Expires", "0");
            
            res.set_redirect(url);
        } else {
            res.status = 404;
            
            // Try to serve a nice 404 page
            std::ifstream file("404.html");
            if (file) {
                std::stringstream buffer;
                buffer << file.rdbuf();
                res.set_content(buffer.str(), "text/html");
            } else {
                res.set_content("URL not found or has expired!", "text/plain");
            }
        }
    });
    
    // URL stats endpoint
    svr.Get("/stats/(\\w+)", [&pool](const httplib::Request &req, httplib::Response &res) {
        std::string code = req.matches[1];
        json result = URLDatabase::getURLStats(pool, code);
        
        int status = result["success"].get<bool>() ? 200 : 404;
        sendJsonResponse(res, status, result);
    });
    
    // QR code generation endpoint
    svr.Get("/qr/(\\w+)", [&pool](const httplib::Request &req, httplib::Response &res) {
        std::string code = req.matches[1];
        std::string url;
        
        if (URLDatabase::getOriginalURL(pool, code, url, false)) {
            std::string short_url = config.base_url + code;
            std::string svg = generateQRCodeSVG(short_url);
            
            res.set_header("Content-Type", "image/svg+xml");
            res.set_content(svg, "image/svg+xml");
        } else {
            res.status = 404;
            res.set_content("URL not found or has expired!", "text/plain");
        }
    });
    
    // User URLs endpoint (with simple token auth)
    svr.Get("/api/urls", [&pool](const httplib::Request &req, httplib::Response &res) {
        // Simple authentication check
        if (!req.has_param("token") || req.get_param_value("token") != config.admin_token) {
            json error = {
                {"status", "error"},
                {"message", "Unauthorized access"}
            };
            sendJsonResponse(res, 401, error);
            return;
        }
        
        int limit = 20;  // Default limit
        int offset = 0;  // Default offset
        
        if (req.has_param("limit")) {
            try {
                limit = std::stoi(req.get_param_value("limit"));
                if (limit < 1) limit = 1;
                if (limit > 100) limit = 100;
            } catch (...) {
                // Use default if invalid
            }
        }
        
        if (req.has_param("offset")) {
            try {
                offset = std::stoi(req.get_param_value("offset"));
                if (offset < 0) offset = 0;
            } catch (...) {
                // Use default if invalid
            }
        }
        
        // For demo, we're using user ID 1 (admin)
        json result = URLDatabase::getAllUserURLs(pool, 1, limit, offset);
        int status = result["success"].get<bool>() ? 200 : 500;
        
        sendJsonResponse(res, status, result);
    });
    
    // Admin dashboard - simple stats overview
    svr.Get("/admin", [&pool](const httplib::Request &req, httplib::Response &res) {
        // Simple token check (query parameter auth for demo)
        if (!req.has_param("token") || req.get_param_value("token") != config.admin_token) {
            res.status = 302;  // Redirect to login
            res.set_header("Location", "/login");
            return;
        }
        
        // Serve admin html template
        std::ifstream file("admin.html");
        if (!file) {
            res.status = 500;
            res.set_content("Could not load admin.html", "text/plain");
            return;
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        res.set_content(buffer.str(), "text/html");
    });
    
    // Health check endpoint
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        json health = {
            {"status", "healthy"},
            {"version", "1.0.0"},
            {"uptime", "unknown"}  // Would calculate from start time in production
        };
        
        sendJsonResponse(res, 200, health);
    });
    
    // Start the server
    Logger::info("Server started at http://localhost:8080");
    Logger::info("URLs will expire after %d hours", config.expiry_hours);
    Logger::info("Base URL: %s", config.base_url.c_str());
    Logger::info("Press Ctrl+C to stop the server");
    
    // Set server options for better performance and compatibility
    svr.set_keep_alive_max_count(1000);        // Max number of keep-alive connections
    svr.set_read_timeout(5, 0);                // 5 seconds read timeout
    svr.set_write_timeout(5, 0);               // 5 seconds write timeout
    svr.set_payload_max_length(1024 * 1024);   // 1MB max payload size
    
    // Start the server on a separate thread so we can listen for the shutdown signal
    std::thread server_thread([&svr]() {
        svr.listen("localhost", 8080);
    });
    
    // Wait for shutdown signal
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // Stop the server gracefully
    Logger::info("Stopping server...");
    svr.stop();
    
    // Wait for threads to finish
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }
    
    // Clean up
    Logger::info("Closing database connections...");
    pool.close();
    
    // Windows-specific cleanup
    #ifdef _WIN32
    WSACleanup();
    #endif
    
    Logger::info("Shutdown complete");
    return 0;
}
