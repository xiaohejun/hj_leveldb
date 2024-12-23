#include <atomic>
#include <iostream>
#include <memory>
#include <cassert>
#include <set>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <mutex>
#include <sys/time.h>
#include <sys/resource.h>
#include "leveldb/env.h"
#include "util/env_posix_test_helper.h"
#include "port/thread_annotations.h"

namespace leveldb {

namespace {

class Limiter {
public:
    Limiter() : acquires_allowed_(MaxAcquires()) {}

    Limiter(const Limiter&) = delete;
    Limiter& operator=(const Limiter&) = delete;

    bool Acquire() {
        int old_val = acquires_allowed_.fetch_sub(1, std::memory_order::memory_order_relaxed);
        if (old_val > 0) {
            return true;
        }

        // old_val <= 0, cur < 0
        acquires_allowed_.fetch_add(1, std::memory_order::memory_order_relaxed);
        return false;
    }

    void Release() {
        acquires_allowed_.fetch_add(1, std::memory_order::memory_order_relaxed);
    }

private:
    virtual int MaxAcquires() = 0;

private:
    std::atomic_int acquires_allowed_;
};

class PosixMMapLimiter final : public Limiter {
private:
    int MaxAcquires() override {
        // 如果是64位操作系统，允许1000个mmap，32位系统，不允许？
        return sizeof(void*) >= 8 ? 1000 : 0;
    }
};

class PosixFdLimiter final : public Limiter {
private:
    int MaxAcquires() override {
        // 默认50个
        int fd_max_acquires = 50;
        struct ::rlimit rlim;
        int ret = ::getrlimit(RLIMIT_NOFILE, &rlim);
        if (ret == -1) {
            return fd_max_acquires;
        }
        // 软限制是内核对相应资源强制执行的值。
        if (rlim.rlim_cur == RLIM_INFINITY) {
            fd_max_acquires = std::numeric_limits<int>::max();
        } else {
            // 20%的fd用于只读文件限制
            fd_max_acquires = rlim.rlim_cur / 5;
        }
        return fd_max_acquires;
    }
};


Status PosixError(const std::string& context, error_t error_number)
{
    if (error_number == ENOENT) {
        return Status::NotFound(context, std::strerror(error_number));
    }
    return Status::IOError(context, std::strerror(error_number));
}

class PosixSequentialFile final : public SequentialFile {
public:
    PosixSequentialFile(int fd, std::string fname) : fd_(fd), fname_(std::move(fname)) {}

    ~PosixSequentialFile() { close(fd_); }

    Status Read(size_t n, Slice* result, char* scratch) override {
        Status s;
        while (true) {
            ssize_t read_size = read(fd_, scratch, n);
            if (read_size == -1) {
                if (errno == EINTR) {
                    // The call was interrupted by a signal before any data was read; see signal(7).
                    // retry
                    continue;
                }
                s = PosixError(fname_, errno);
                break;
            }
            *result = Slice(scratch, read_size);
            break;
        }
        return s; 
    }

    Status Skip(size_t n) override {
        Status s;
        if (lseek(fd_, n, SEEK_CUR) == static_cast<off_t>(-1)) {
            s = PosixError(fname_, errno);
        }
        return s;
    }

private:
    int fd_;
    const std::string fname_;
};

// Common flags defined for all posix open operations
#if defined(HAVE_O_CLOEXEC)
constexpr const int kOpenBaseFlags = O_CLOEXEC;
#else
constexpr const int kOpenBaseFlags = 0;
#endif  // defined(HAVE_O_CLOEXEC)


class PosixRandomAccessFile final : public RandomAccessFile {
public:
    PosixRandomAccessFile(int fd, std::string fname, PosixFdLimiter* fd_limiter)
        : has_permanent_fd_(fd_limiter_->Acquire()),
            fd_(has_permanent_fd_ ? fd : -1), fname_(std::move(fname)),
            fd_limiter_(fd_limiter) {
            if (!has_permanent_fd_) {
                assert(fd != -1);
                close(fd);
            }
    }

    Status Read(uint64_t offset, size_t n, Slice* result, char* scratch) override {
        Status s;
        if (!has_permanent_fd_) {
            fd_ = open(fname_.c_str(), O_RDONLY | kOpenBaseFlags);
            if (fd_ == -1) {
                s = PosixError(fname_, errno);
                return s;
            }
        }

        ssize_t read_size = pread(fd_, scratch, n, static_cast<off_t>(offset));
        if (read_size == -1) {
            s = PosixError(fname_, errno);
            return s;
        }
        *result = Slice(scratch, read_size);

        if (!has_permanent_fd_) {
            close(fd_);
        }

        return s;
    }

private:
    bool has_permanent_fd_;
    int fd_;
    const std::string fname_;
    PosixFdLimiter* const fd_limiter_;
};

class PosixMmapReadableFile final : public RandomAccessFile {
public:
    PosixMmapReadableFile(std::string fname, char *mmap_base, size_t length, PosixMMapLimiter* mmap_limiter)
        : fname_(std::move(fname)), mmap_base_(mmap_base), length_(length), mmap_limiter_(mmap_limiter_) {}

    ~PosixMmapReadableFile() {
        munmap(static_cast<void*>(mmap_base_), length_);
        mmap_limiter_->Release();
    }

    Status Read(uint64_t offset, size_t n, Slice* result, char* scratch) override {
        if (offset + n > length_) {
            *result = Slice();
            return PosixError(fname_, EINVAL);
        }

        *result = Slice(mmap_base_ + offset, n);
        return Status::OK();
    }

private:
    char* const mmap_base_;
    const size_t length_;
    PosixMMapLimiter* const mmap_limiter_;
    const std::string fname_;
};

class PosixWritableFile final : public WritableFile {
public:
    PosixWritableFile(std::string fname, int fd) :
        pos_(0),
        fd_(fd),
        is_manifest_(IsManifest(fname)),
        fname_(std::move(fname)),
        dirname_(Dirname(fname)) {}
    
    ~PosixWritableFile() override {
        if (fd_ >= 0) {
            (void)Close();
        }
    }
    Status Append(const Slice& data) override {
        size_t write_size = data.size();
        const char* write_data = data.data();

        // 先尽量放入buffer里面
        size_t copy_size = std::min(write_size, kBufferSize - pos_);
        std::memcpy(buffer_, write_data, copy_size);
        write_size -= copy_size;
        write_data += copy_size;
        pos_ += copy_size;
        if (write_size == 0) {
            // buffer还没有满
           return Status::OK();
        }

        // write_size > 0，buffer满了，还有一些没有装入buffer
        // 先把buffer刷新一下
        Status s = FlushBuffer();
        if (!s.ok()) {
            return s;
        }

        // buffer刷新完毕了，剩下的可以放入buffer就先放入buffer
        if (write_size < kBufferSize) {
            std::memcpy(buffer_, write_data, write_size);
            pos_ = write_size;
            return Status::OK();
        }

        // buffer刷新完毕，剩下的没办法放入buffer，直接刷新
        return WriteUnBuffered(write_data, write_size);
    }

    Status Close() override {
        Status s = FlushBuffer();
        int ret = close(fd_);
        if (ret == -1 && s.ok()) {
            s = PosixError(fname_, errno);
        }
        fd_ = -1;
        return s;
    }

    Status Flush() override {
        return FlushBuffer();
    }

    Status Sync() override {
        Status s = SyncDirIfMainfest();
        if (!s.ok()) {
            return s;
        }

        s = FlushBuffer();
        if (!s.ok()) {
            return s;
        }

        return SyncFd(fd_, fname_);
    }

private:
    Status FlushBuffer() {
        Status s = WriteUnBuffered(buffer_, pos_);
        pos_ = 0;
        return s;
    }

    Status WriteUnBuffered(const char* data, size_t size) {
        while (size > 0) {
            ssize_t write_size = write(fd_, data, size);
            if (write_size < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return PosixError(fname_, errno);
            }
            data += write_size;
            size -= write_size;
        }
        return Status::OK();
    }

    Status SyncDirIfMainfest() {
        Status s;
        if (!is_manifest_) {
            return s;
        }

        int fd = open(dirname_.c_str(), O_RDONLY | kOpenBaseFlags);
        if (fd < 0) {
            s = PosixError(fname_, errno);
        } else {
            s = SyncFd(fd, dirname_);
            close(fd);
        }

        return s;
    }

    static Status SyncFd(int fd, const std::string& fd_path) {
    #if HAVE_FULLFSYNC
        if (fcntl(fd, F_FULLFSYNC)) {
            return Stats::OK();
        }
    #endif

    #if HAVE_FDATASYNC
        bool sync_success = fdatasync(fd);
    #else
        bool sync_success = fsync(fd);
    #endif
        if (sync_success) {
            return Status::OK();
        }
        return PosixError(fd_path, errno);
    }

    static bool IsManifest(const std::string& fname) {
        return Basename(fname).starts_with("MANIFEST");
    }

    static Slice Basename(const std::string& fname) {
        auto pos = fname.rfind('/');
        if (pos == std::string::npos) {
            return Slice(fname);
        }

        assert(fname.find('/', pos + 1) == std::string::npos);

        return Slice(fname.data() + pos + 1, fname.length() - pos - 1);
    }

    static std::string Dirname(const std::string& fname) {
        auto pos = fname.rfind('/');
        if (pos == std::string::npos) {
            return std::string(".");
        }

        assert(fname.find('/', pos + 1) == std::string::npos);

        return fname.substr(0, pos);
    }

    static constexpr size_t kBufferSize = 64 * 1024;

    char buffer_[kBufferSize];
    size_t pos_;
    int fd_;

    const bool is_manifest_;
    const std::string fname_;
    const std::string dirname_;
};

int LockOrUnlock(int fd, bool lock)
{
    errno = 0;
    struct ::flock file_lock_info;
    std::memset(&file_lock_info, 0, sizeof(file_lock_info));
    file_lock_info.l_type = (lock ? F_WRLCK : F_UNLCK);
    file_lock_info.l_whence = SEEK_SET;
    file_lock_info.l_start = 0;
    file_lock_info.l_len = 0; // lock/unlock entire file
    return fcntl(fd, F_SETLK, &file_lock_info);
}

class PosixFileLock final : public FileLock {
public:
    PosixFileLock(int fd, std::string fname)
        : fd_(fd), fname_(std::move(fname)) {}
    
    int fd() const { return fd_; }

    const std::string& filename() const { return fname_; }

private:
    const int fd_;
    const std::string fname_;
};

/**
 * @brief 跟踪由 PosixEnv::LockFile() 锁定的文件。
 * 我们维护一个单独的集合，而不是依赖 fcntl(F_SETLK)，因为 fcntl(F_SETLK) 不提供任何针对同一进程多次使用的保护。
 * 
 */
class PosixLockFileTable {
public:
    bool Insert(const std::string& fname) {
        std::lock_guard<std::mutex> lk(mu_);
        return lock_files_.insert(fname).second;
    }

    void Remove(const std::string& fname) {
        std::lock_guard<std::mutex> lk(mu_);
        lock_files_.erase(fname);
    }

private:
    std::mutex mu_;
    std::set<std::string> lock_files_ GUARDED_BY(mu_);
};

class PosixEnv : public Env {
    PosixEnv() = default;
    ~PosixEnv() {
        std::cerr << "PosixEnv singleton destoryed. Unsupported behavior!\n" << std::endl;
        std::abort();
    } 

    Status NewSequentialFile(const std::string& fname, SequentialFile** result) override {
        *result = nullptr;
        int fd = ::open(fname.c_str(), O_RDONLY | kOpenBaseFlags);
        if (fd == -1) {
            return PosixError(fname, errno);
        }
        *result = new PosixSequentialFile(fd, fname);
        return Status::OK();
    }

    Status NewRandomAccessFile(const std::string& fname, RandomAccessFile** result) override {
        *result = nullptr;
        int fd = ::open(fname.c_str(), O_RDONLY | kOpenBaseFlags);
        if (fd == -1) {
            return PosixError(fname, errno);
        }

        // TODO 测试mmap和posix读取文件的性能差异
        // 优先使用mmap打开文件
        if (mmap_limter_.Acquire()) {
            uint64_t file_size = 0;
            Status s = GetFileSize(fname, &file_size);
            if (s.ok()) {
                void* mmap_base = ::mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);
                if (mmap_base == MAP_FAILED) {
                    s = PosixError(fname, errno);
                } else {
                    *result = new PosixMmapReadableFile(fname, reinterpret_cast<char*>(mmap_base), file_size, &mmap_limter_);
                    s = Status::OK();
                }
           }
            // 当前只需要读取，所以可以关闭fd
            ::close(fd); 
            if (!s.ok()) {
                mmap_limter_.Release();
            }
            return s;
        }

        // 再使用普通的方式打开文件
        *result = new PosixRandomAccessFile(fd, fname, &fd_limiter_);
        return Status::OK();
    }

    Status NewWritableFile(const std::string& fname, WritableFile** result) override {
        *result = nullptr;
        int fd = ::open(fname.c_str(), O_CREAT | O_TRUNC | O_WRONLY | kOpenBaseFlags, kNewFileMode);
        if (fd == -1) {
            return PosixError(fname, errno);
        }

        *result = new PosixWritableFile(fname, fd);
        return Status::OK();
    }

    Status NewAppendableFile(const std::string& fname, WritableFile** result) override {
        *result = nullptr;
        int fd = ::open(fname.c_str(), O_CREAT | O_WRONLY | O_APPEND | kOpenBaseFlags, kNewFileMode);
        if (fd == -1) {
            return PosixError(fname, errno);
        }

        *result = new PosixWritableFile(fname, fd);
        return Status::OK();
    }

    

private:

    /**
     * @brief 新创建的文件权限设置
     * 创建者：读、写
     * 组用户：读
     * 其他用户：读
     */
    static constexpr mode_t kNewFileMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    PosixLockFileTable lock_files_; // thread-safe
    PosixFdLimiter fd_limiter_; // thread-safe
    PosixMMapLimiter mmap_limter_; // thread-safe
};

// Wraps an Env instance whose destructor is never created.
//
// Intended usage:
//   using PlatformSingletonEnv = SingletonEnv<PlatformEnv>;
//   void ConfigurePosixEnv(int param) {
//     PlatformSingletonEnv::AssertEnvNotInitialized();
//     // set global configuration flags.
//   }
//   Env* Env::Default() {
//     static PlatformSingletonEnv default_env;
//     return default_env.env();
//   }
template <typename EnvType>
class SingletonEnv {
public:
    SingletonEnv() {
        #if !defined(NDEBUG)
            env_initialized_.store(true, std::memory_order::memory_order_relaxed);
        #endif // !defined(NDEBUG)
 
        static_assert(sizeof(env_storage_) >= sizeof(EnvType),
            "env_storage_ will not fit the Env");
        
        static_assert(alignof(env_storage_) >= alignof(EnvType),
            "env_storage_ does not meet the Env's alignment needs");

        new (&env_storage_) EnvType();
    }

    ~SingletonEnv() = default;

    SingletonEnv(const SingletonEnv&) = delete;
    SingletonEnv& operator=(const SingletonEnv&) = delete;

    Env* env() { return reinterpret_cast<Env*>(env_storage_); }

    static void AssertEnvNotInitialized() {
    #if !defined(NDEBUG)
        assert(!env_initialized_.load(std::memory_order::memory_order_relaxed));
    #endif // !defined(NDEBUG)
    }

private:
    typename std::aligned_storage<sizeof(EnvType), alignof(EnvType)>::type env_storage_;

#if !defined(NDEBUG)
    static std::atomic<bool> env_initialized_;
#endif // !defined(NDEBUG)
};

#if !defined(NDEBUG)
template <typename EnvType>
std::atomic<bool> SingletonEnv<EnvType>::env_initialized_;
#endif  // !defined(NDEBUG)

using PosixDefaultEnv = SingletonEnv<PosixEnv>;
    
}; // namespace

void EnvPosixTestHelper::SetReadOnlyFdLimit(int limit)
{
    PosixDefaultEnv::AssertEnvNotInitialized();
    g_open_read_only_file_limit = limit;
}

void EnvPosixTestHelper::SetReadOnlyMMapLimit(int limit)
{
    PosixDefaultEnv::AssertEnvNotInitialized();
    g_mmap_limit = limit;
}

Env* Env::Defalut() {
    static PosixDefaultEnv env_container;
    return env_container.env();
}

} // namespace leveldb
