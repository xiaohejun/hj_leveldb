#ifndef STORAGE_LEVELDB_UTIL_POSIX_LOGGER_H_
#define STORAGE_LEVELDB_UTIL_POSIX_LOGGER_H_

#include <sys/time.h>
#include <thread>
#include <cassert>
#include <sstream>
#include "leveldb/env.h"

namespace leveldb {

class PosixLogger final : public Logger {
public:
    PosixLogger(FILE* file) : file_(file) {}
    ~PosixLogger() { ::fclose(file_); }

    /**
     * @brief 打印日志是线程安全的，因为只是一直往日志文件里面append数据
     * 
     * @param format 
     * @param ap 
     */
    void LogV(const char* format, std::va_list ap) override {
        // 拼接日志信息的时候优先使用栈内存，因为栈内存开辟比堆内存快，
        // 还有如果是打印少量的日志的时候，避免频繁开辟小块堆内存，
        // 造成大量的内存碎片
        static constexpr uint8_t kBuffsize = 512;
        static char stack_buffer[kBuffsize];

        // 获取时间戳
        struct ::timeval tv;
        ::gettimeofday(&tv, nullptr);
        struct ::tm result;
        ::localtime_r(&tv.tv_sec, &result);
        int offset = 0;
        int cur = std::snprintf(stack_buffer + offset, kBuffsize - offset,
            "%04d/%02d/%02d-%02d:%02d:%02d.%06d",
            result.tm_year + 1970, result.tm_mon + 1, result.tm_mday,
            result.tm_hour, result.tm_min, result.tm_sec, tv.tv_usec);
        // 当前只是加入了一个时间戳，不应该出错
        assert(cur > 0);
        offset += cur;
        assert(offset < kBuffsize);

        // 获取线程ID
        std::ostringstream ss;
        ss << std::this_thread::get_id();
        cur = std::snprintf(stack_buffer + offset, kBuffsize - offset, " %s ", ss.str().c_str());
        // 当前只是加了时间戳和线程ID，不应该出错
        assert(cur > 0);
        offset += cur;
        assert(offset < kBuffsize);

        std::va_list ap_copy;
        va_copy(ap_copy, ap);
        // cur返回实际写入的字节，不包含'\0'
        cur = std::vsnprintf(stack_buffer + offset, kBuffsize - offset, format, ap_copy);
        va_end(ap_copy);
        assert(cur >= 0);

        char *real_use_buffer = stack_buffer;
        // +2 是预留一个'\n'和'\0'
        int need_size = offset + cur + 2;
        if (need_size > kBuffsize) {
            real_use_buffer = new char[need_size];
            std::memcpy(real_use_buffer, stack_buffer, offset);
            va_copy(ap_copy, ap);
            cur = std::vsnprintf(real_use_buffer, need_size - offset, format, ap_copy);
            va_end(ap_copy);
            assert(cur >= 0);
        }
        offset += cur;
        real_use_buffer[offset++] = '\0';
        real_use_buffer[offset++] = '\n';

        // 要写入的日志拼接完成了，写入stream并且刷新stream
        std::fwrite(real_use_buffer, 1, offset, file_);
        std::fflush(file_);
    }

private:
    FILE* const file_;
};


};

#endif // STORAGE_LEVELDB_UTIL_POSIX_LOGGER_H_