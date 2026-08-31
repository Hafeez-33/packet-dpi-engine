#include "dpi/rules/rule_parser.h"
#include "dpi/rules/domain_matcher.h"
#include "dpi/rules/ip_matcher.h"
#include "dpi/rules/port_matcher.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <variant>

namespace dpi {

namespace json {

enum class TokenType {
    LeftBrace, RightBrace, LeftBracket, RightBracket,
    Colon, Comma, String, Number, Boolean, Null, EndOfFile, Error
};

struct Token {
    TokenType type{TokenType::EndOfFile};
    std::string string_val{};
    double number_val{0.0};
    bool bool_val{false};
    size_t line{1};
};

class Lexer {
public:
    explicit Lexer(std::string_view src) : src_(src) {}

    Token next_token() {
        skip_whitespace();
        if (pos_ >= src_.size()) {
            return Token{TokenType::EndOfFile, "", 0.0, false, line_};
        }

        char c = src_[pos_];
        if (c == '{') { ++pos_; return Token{TokenType::LeftBrace, "{", 0.0, false, line_}; }
        if (c == '}') { ++pos_; return Token{TokenType::RightBrace, "}", 0.0, false, line_}; }
        if (c == '[') { ++pos_; return Token{TokenType::LeftBracket, "[", 0.0, false, line_}; }
        if (c == ']') { ++pos_; return Token{TokenType::RightBracket, "]", 0.0, false, line_}; }
        if (c == ':') { ++pos_; return Token{TokenType::Colon, ":", 0.0, false, line_}; }
        if (c == ',') { ++pos_; return Token{TokenType::Comma, ",", 0.0, false, line_}; }

        if (c == '"') {
            return lex_string();
        }

        if (std::isdigit(static_cast<unsigned char>(c)) || c == '-') {
            return lex_number();
        }

        if (std::isalpha(static_cast<unsigned char>(c))) {
            return lex_keyword();
        }

        ++pos_;
        return Token{TokenType::Error, std::string(1, c), 0.0, false, line_};
    }

    size_t current_line() const noexcept { return line_; }

private:
    void skip_whitespace() {
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == '\n') {
                ++line_;
                ++pos_;
            } else if (c == ' ' || c == '\t' || c == '\r') {
                ++pos_;
            } else if (c == '/' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '/') {
                // Line comment support
                pos_ += 2;
                while (pos_ < src_.size() && src_[pos_] != '\n') {
                    ++pos_;
                }
            } else {
                break;
            }
        }
    }

    Token lex_string() {
        size_t start_line = line_;
        ++pos_; // skip opening quote
        std::string val;
        while (pos_ < src_.size()) {
            char c = src_[pos_++];
            if (c == '"') {
                return Token{TokenType::String, val, 0.0, false, start_line};
            }
            if (c == '\\' && pos_ < src_.size()) {
                char esc = src_[pos_++];
                if (esc == '"') val.push_back('"');
                else if (esc == '\\') val.push_back('\\');
                else if (esc == '/') val.push_back('/');
                else if (esc == 'b') val.push_back('\b');
                else if (esc == 'f') val.push_back('\f');
                else if (esc == 'n') val.push_back('\n');
                else if (esc == 'r') val.push_back('\r');
                else if (esc == 't') val.push_back('\t');
                else val.push_back(esc);
            } else {
                if (c == '\n') ++line_;
                val.push_back(c);
            }
        }
        return Token{TokenType::Error, "Unterminated string", 0.0, false, start_line};
    }

    Token lex_number() {
        size_t start_line = line_;
        size_t start = pos_;
        if (src_[pos_] == '-') ++pos_;
        while (pos_ < src_.size() && (std::isdigit(static_cast<unsigned char>(src_[pos_])) || src_[pos_] == '.')) {
            ++pos_;
        }
        std::string num_str(src_.substr(start, pos_ - start));
        try {
            double val = std::stod(num_str);
            return Token{TokenType::Number, num_str, val, false, start_line};
        } catch (...) {
            return Token{TokenType::Error, "Invalid number: " + num_str, 0.0, false, start_line};
        }
    }

    Token lex_keyword() {
        size_t start_line = line_;
        size_t start = pos_;
        while (pos_ < src_.size() && std::isalpha(static_cast<unsigned char>(src_[pos_]))) {
            ++pos_;
        }
        std::string kw(src_.substr(start, pos_ - start));
        if (kw == "true") return Token{TokenType::Boolean, kw, 0.0, true, start_line};
        if (kw == "false") return Token{TokenType::Boolean, kw, 0.0, false, start_line};
        if (kw == "null") return Token{TokenType::Null, kw, 0.0, false, start_line};
        return Token{TokenType::Error, "Unknown keyword: " + kw, 0.0, false, start_line};
    }

    std::string_view src_;
    size_t pos_{0};
    size_t line_{1};
};

struct JsonValue;
using JsonObject = std::map<std::string, JsonValue>;
using JsonArray = std::vector<JsonValue>;

struct JsonValue {
    enum class Type { Null, Boolean, Number, String, Array, Object };
    Type type{Type::Null};
    std::variant<std::monostate, bool, double, std::string, JsonArray, JsonObject> data;

    bool is_null() const noexcept { return type == Type::Null; }
    bool is_bool() const noexcept { return type == Type::Boolean; }
    bool is_number() const noexcept { return type == Type::Number; }
    bool is_string() const noexcept { return type == Type::String; }
    bool is_array() const noexcept { return type == Type::Array; }
    bool is_object() const noexcept { return type == Type::Object; }

    bool as_bool() const { return std::get<bool>(data); }
    double as_number() const { return std::get<double>(data); }
    const std::string& as_string() const { return std::get<std::string>(data); }
    const JsonArray& as_array() const { return std::get<JsonArray>(data); }
    const JsonObject& as_object() const { return std::get<JsonObject>(data); }
};

class Parser {
public:
    explicit Parser(std::string_view src) : lexer_(src) {
        advance();
    }

    bool parse(JsonValue& root, std::string& err_msg, size_t& err_line) {
        if (curr_.type == TokenType::Error) {
            err_msg = curr_.string_val;
            err_line = curr_.line;
            return false;
        }
        return parse_value(root, err_msg, err_line);
    }

private:
    void advance() {
        curr_ = lexer_.next_token();
    }

    bool parse_value(JsonValue& val, std::string& err_msg, size_t& err_line) {
        switch (curr_.type) {
            case TokenType::Null:
                val.type = JsonValue::Type::Null;
                val.data = std::monostate{};
                advance();
                return true;
            case TokenType::Boolean:
                val.type = JsonValue::Type::Boolean;
                val.data = curr_.bool_val;
                advance();
                return true;
            case TokenType::Number:
                val.type = JsonValue::Type::Number;
                val.data = curr_.number_val;
                advance();
                return true;
            case TokenType::String:
                val.type = JsonValue::Type::String;
                val.data = curr_.string_val;
                advance();
                return true;
            case TokenType::LeftBracket:
                return parse_array(val, err_msg, err_line);
            case TokenType::LeftBrace:
                return parse_object(val, err_msg, err_line);
            default:
                err_msg = "Unexpected token: " + curr_.string_val;
                err_line = curr_.line;
                return false;
        }
    }

    bool parse_array(JsonValue& val, std::string& err_msg, size_t& err_line) {
        advance(); // skip '['
        val.type = JsonValue::Type::Array;
        JsonArray arr;

        if (curr_.type == TokenType::RightBracket) {
            advance();
            val.data = std::move(arr);
            return true;
        }

        while (true) {
            JsonValue elem;
            if (!parse_value(elem, err_msg, err_line)) {
                return false;
            }
            arr.push_back(std::move(elem));

            if (curr_.type == TokenType::Comma) {
                advance();
            } else if (curr_.type == TokenType::RightBracket) {
                advance();
                break;
            } else {
                err_msg = "Expected ',' or ']' in array";
                err_line = curr_.line;
                return false;
            }
        }
        val.data = std::move(arr);
        return true;
    }

    bool parse_object(JsonValue& val, std::string& err_msg, size_t& err_line) {
        advance(); // skip '{'
        val.type = JsonValue::Type::Object;
        JsonObject obj;

        if (curr_.type == TokenType::RightBrace) {
            advance();
            val.data = std::move(obj);
            return true;
        }

        while (true) {
            if (curr_.type != TokenType::String) {
                err_msg = "Expected string key in object";
                err_line = curr_.line;
                return false;
            }
            std::string key = curr_.string_val;
            advance();

            if (curr_.type != TokenType::Colon) {
                err_msg = "Expected ':' after key '" + key + "'";
                err_line = curr_.line;
                return false;
            }
            advance();

            JsonValue member_val;
            if (!parse_value(member_val, err_msg, err_line)) {
                return false;
            }
            obj[key] = std::move(member_val);

            if (curr_.type == TokenType::Comma) {
                advance();
            } else if (curr_.type == TokenType::RightBrace) {
                advance();
                break;
            } else {
                err_msg = "Expected ',' or '}' in object";
                err_line = curr_.line;
                return false;
            }
        }
        val.data = std::move(obj);
        return true;
    }

    Lexer lexer_;
    Token curr_;
};

} // namespace json

RuleLoadResult RuleParser::parse_string(std::string_view json_content) noexcept {
    RuleLoadResult res;
    if (json_content.empty()) {
        res.success = false;
        res.error_message = "Empty JSON input";
        res.error_line = 1;
        return res;
    }

    json::Parser parser(json_content);
    json::JsonValue root;
    std::string err_msg;
    size_t err_line = 1;

    if (!parser.parse(root, err_msg, err_line)) {
        res.success = false;
        res.error_message = err_msg;
        res.error_line = err_line;
        return res;
    }

    if (!root.is_object()) {
        res.success = false;
        res.error_message = "Root JSON must be an object";
        res.error_line = 1;
        return res;
    }

    const auto& root_obj = root.as_object();

    // Parse default_action
    if (root_obj.count("default_action")) {
        const auto& def_act = root_obj.at("default_action");
        if (def_act.is_string()) {
            res.default_action = string_to_rule_action(def_act.as_string());
        }
    }

    // Parse rules
    if (!root_obj.count("rules")) {
        res.success = false;
        res.error_message = "Missing 'rules' section in JSON configuration";
        res.error_line = 1;
        return res;
    }

    const auto& rules_val = root_obj.at("rules");
    uint32_t auto_id = 1;

    if (rules_val.is_array()) {
        // Structured Rule Array Format
        for (const auto& r_elem : rules_val.as_array()) {
            if (!r_elem.is_object()) {
                res.success = false;
                res.error_message = "Rule elements in array must be objects";
                return res;
            }
            const auto& robj = r_elem.as_object();
            Rule r;
            r.id = auto_id++;
            if (robj.count("id") && robj.at("id").is_number()) {
                r.id = static_cast<uint32_t>(robj.at("id").as_number());
            }
            if (robj.count("name") && robj.at("name").is_string()) {
                r.name = robj.at("name").as_string();
            }
            if (robj.count("priority") && robj.at("priority").is_number()) {
                r.priority = static_cast<uint32_t>(robj.at("priority").as_number());
            }
            if (robj.count("enabled") && robj.at("enabled").is_bool()) {
                r.enabled = robj.at("enabled").as_bool();
            }
            if (robj.count("action") && robj.at("action").is_string()) {
                r.action = string_to_rule_action(robj.at("action").as_string());
            }

            if (robj.count("src_ip") && robj.at("src_ip").is_string()) {
                r.src_ip_cidr = robj.at("src_ip").as_string();
            } else if (robj.count("src_ip_cidr") && robj.at("src_ip_cidr").is_string()) {
                r.src_ip_cidr = robj.at("src_ip_cidr").as_string();
            }

            if (robj.count("dst_ip") && robj.at("dst_ip").is_string()) {
                r.dst_ip_cidr = robj.at("dst_ip").as_string();
            } else if (robj.count("dst_ip_cidr") && robj.at("dst_ip_cidr").is_string()) {
                r.dst_ip_cidr = robj.at("dst_ip_cidr").as_string();
            }

            if (robj.count("src_port") && robj.at("src_port").is_string()) {
                r.src_port_range = robj.at("src_port").as_string();
            } else if (robj.count("src_port") && robj.at("src_port").is_number()) {
                r.src_port_range = std::to_string(static_cast<uint16_t>(robj.at("src_port").as_number()));
            }

            if (robj.count("dst_port") && robj.at("dst_port").is_string()) {
                r.dst_port_range = robj.at("dst_port").as_string();
            } else if (robj.count("dst_port") && robj.at("dst_port").is_number()) {
                r.dst_port_range = std::to_string(static_cast<uint16_t>(robj.at("dst_port").as_number()));
            }

            if (robj.count("protocol") && robj.at("protocol").is_string()) {
                r.transport_protocol = robj.at("protocol").as_string();
            }
            if (robj.count("domain") && robj.at("domain").is_string()) {
                r.domain_pattern = robj.at("domain").as_string();
            }
            if (robj.count("app_protocol") && robj.at("app_protocol").is_string()) {
                r.app_protocol = robj.at("app_protocol").as_string();
            }

            // Semantic validation
            if (!r.src_ip_cidr.empty() && !IpMatcher::parse(r.src_ip_cidr).is_valid()) {
                res.success = false;
                res.error_message = "Invalid src_ip CIDR format: " + r.src_ip_cidr;
                return res;
            }
            if (!r.dst_ip_cidr.empty() && !IpMatcher::parse(r.dst_ip_cidr).is_valid()) {
                res.success = false;
                res.error_message = "Invalid dst_ip CIDR format: " + r.dst_ip_cidr;
                return res;
            }
            if (!r.src_port_range.empty() && !PortMatcher::parse(r.src_port_range).is_valid()) {
                res.success = false;
                res.error_message = "Invalid src_port expression: " + r.src_port_range;
                return res;
            }
            if (!r.dst_port_range.empty() && !PortMatcher::parse(r.dst_port_range).is_valid()) {
                res.success = false;
                res.error_message = "Invalid dst_port expression: " + r.dst_port_range;
                return res;
            }

            res.rules.push_back(std::move(r));
        }
    } else if (rules_val.is_object()) {
        // Categorical Section Format (e.g. blocked_ips, blocked_domains, blocked_ports, blocked_apps)
        const auto& cat_obj = rules_val.as_object();

        if (cat_obj.count("blocked_ips") && cat_obj.at("blocked_ips").is_array()) {
            for (const auto& item : cat_obj.at("blocked_ips").as_array()) {
                if (item.is_string()) {
                    Rule r;
                    r.id = auto_id++;
                    r.name = "Block IP: " + item.as_string();
                    r.priority = 50;
                    r.action = RuleAction::Block;
                    r.dst_ip_cidr = item.as_string();
                    if (!IpMatcher::parse(r.dst_ip_cidr).is_valid()) {
                        res.success = false;
                        res.error_message = "Invalid blocked_ip: " + r.dst_ip_cidr;
                        return res;
                    }
                    res.rules.push_back(std::move(r));
                }
            }
        }

        if (cat_obj.count("blocked_domains") && cat_obj.at("blocked_domains").is_array()) {
            for (const auto& item : cat_obj.at("blocked_domains").as_array()) {
                if (item.is_string()) {
                    Rule r;
                    r.id = auto_id++;
                    r.name = "Block Domain: " + item.as_string();
                    r.priority = 60;
                    r.action = RuleAction::Block;
                    r.domain_pattern = item.as_string();
                    res.rules.push_back(std::move(r));
                }
            }
        }

        if (cat_obj.count("blocked_ports") && cat_obj.at("blocked_ports").is_array()) {
            for (const auto& item : cat_obj.at("blocked_ports").as_array()) {
                Rule r;
                r.id = auto_id++;
                r.priority = 40;
                r.action = RuleAction::Block;
                if (item.is_number()) {
                    r.dst_port_range = std::to_string(static_cast<uint16_t>(item.as_number()));
                } else if (item.is_string()) {
                    r.dst_port_range = item.as_string();
                }
                r.name = "Block Port: " + r.dst_port_range;
                if (!PortMatcher::parse(r.dst_port_range).is_valid()) {
                    res.success = false;
                    res.error_message = "Invalid blocked_port: " + r.dst_port_range;
                    return res;
                }
                res.rules.push_back(std::move(r));
            }
        }

        if (cat_obj.count("blocked_apps") && cat_obj.at("blocked_apps").is_array()) {
            for (const auto& item : cat_obj.at("blocked_apps").as_array()) {
                if (item.is_string()) {
                    std::string app = item.as_string();
                    std::string upper_app = app;
                    std::transform(upper_app.begin(), upper_app.end(), upper_app.begin(),
                                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

                    if (upper_app != "TLS" && upper_app != "HTTP" && upper_app != "DNS" && upper_app != "ANY") {
                        res.success = false;
                        res.error_message = "Unsupported application protocol in blocked_apps: " + app +
                                            " (supported: TLS, HTTP, DNS)";
                        return res;
                    }

                    Rule r;
                    r.id = auto_id++;
                    r.name = "Block App: " + app;
                    r.priority = 70;
                    r.action = RuleAction::Block;
                    r.app_protocol = upper_app;
                    res.rules.push_back(std::move(r));
                }
            }
        }
    } else {
        res.success = false;
        res.error_message = "'rules' must be either an array of rules or a category object";
        return res;
    }

    res.success = true;
    return res;
}

RuleLoadResult RuleParser::parse_file(const std::string& filepath) noexcept {
    RuleLoadResult res;
    std::ifstream file(filepath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        res.success = false;
        res.error_message = "Could not open rule file: " + filepath;
        return res;
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return parse_string(ss.str());
}

} // namespace dpi
