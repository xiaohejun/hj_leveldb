#ifndef STORAGE_LEVELDB_INCLUDE_ENV_H_
#define STORAGE_LEVELDB_INCLUDE_ENV_H_

#include <string>
#include <vector>
#include <cstdarg>

#include "leveldb/export.h"
#include "leveldb/status.h"

namespace leveldb {

class SequentialFile;
class RandomAccessFile;
class WritableFile;
class FileLock;
class Logger;

class LEVELDB_EXPORT Env {
 public:
  Env();

  Env(const Env&) = delete;
  Env& operator=(const Env&) = delete;

  virtual ~Env();

  /**
   * @brief 根据当前操作系统返回默认的Env对象，Env对象在leveldb存在期间
   * 永远不会被删除，用户可以自定义自己的Env对象
   *
   * @return Env*
   */
  static Env* Default();

  /**
   * @brief 创建一个SequentialFile对象用于顺序读文件，文件的路径名是fname
   * 返回的文件同一时间只能由一个线程进行访问
   *
   * @param fname 文件路径名
   * @param result 存储一个SequentialFile对象指针到*result中
   * @return Status 返回结果有以下情况
   * 成功的时候：返回OK，并且设置*result的值为一个SequentialFile对象
   * 失败的时候：返回OK之外的值，*result设置为nullptr
   * 特别的：如果fname路径下文件不存在返回NotFound
   */
  virtual Status NewSequentialFile(const std::string& fname,
                                   SequentialFile** result) = 0;

  /**
   * @brief 创建一个RandomAccessFile对象用于随机读文件，文件的路径名是fname
   * 返回的文件同一时间只能由一个线程进行访问
   *
   * @param fname 文件路径名
   * @param result 存储一个RandomAccessFile对象指针到*result中
   * @return Status 返回结果有以下情况
   * 成功的时候：返回OK，并且设置*result的值为一个RandomAccessFile对象
   * 失败的时候：返回OK之外的值，*result设置为nullptr
   * 特别的：如果fname路径下文件不存在返回NotFound
   */
  virtual Status NewRandomAccessFile(const std::string& fname,
                                     RandomAccessFile** result) = 0;

  /**
   * @brief
   * 创建一个WritableFile对象可用于写文件，文件路径是fname，如果fname文件存在，则先删除该文件
   * 返回的文件同一时间只能由一个线程进行访问
   *
   * @param fname 文件路径名
   * @param result 存储一个WritableFile对象指针到*result中
   * @return Status 返回结果有以下情况
   * 成功的时候：返回OK，并且设置*result的值为一个WritableFile对象
   * 失败的时候：返回OK之外的值，*result设置为nullptr
   */
  virtual Status NewWritableFile(const std::string& fname,
                                 WritableFile** result) = 0;

  /**
   * @brief
   * 创建一个WritableFile对象用于在一个已经存在的文件fname后面继续写，如果文件不存在，则创建
   * 并且从头开始写，返回的文件同一时间只能由一个线程进行访问
   *
   * @param fname 文件路径
   * @param result 存储一个WritableFile对象到指针*result中
   * @return Status  返回结果有以下情况
   * 成功的时候：返回OK，并且设置*result的值为一个WritableFile对象
   * 失败的时候：返回OK之外的值，*result设置为nullptr
   */
  virtual Status NewAppendableFile(const std::string& fname,
                                   WritableFile** result);

  /**
   * @brief 检查文件是否存在
   *
   * @param fname 文件路径
   * @return true 文件fname存在
   * @return false 文件fname不存在
   */
  virtual bool FileExists(const std::string& fname) = 0;

  /**
   * @brief
   * 首先清空*result中的内容，获取dir目录中所有的文件名存储到*result中，文件名的路径相对于dir
   *
   * @param dir 目录
   * @param result dir下的所有文件，第一层
   * @return Status 是否成功
   */
  virtual Status GetChildren(const std::string& dir,
                             std::vector<std::string>* result) = 0;

  /**
   * @brief 删除文件fname，默认实现调用DeleteFile，需要实现Env的子类
   * 请覆写RemoveFile函数，保持DeleteFile的默认实现，最新的代码最好调用
   * RemoveFile函数，而不是调用DeleteFile函数
   *
   * @param fname 要删除的文件
   * @return Status 是否成功
   */
  virtual Status RemoveFile(const std::string& fname);

  /**
   * @brief 该方法即将废弃，子类Env覆写RemoveFile函数，使用RemoveFile函数，
   * 不要覆DeleteFile函数，也不要使用DeleteFile函数
   *
   * @param fname
   * @return Status
   */
  virtual Status DeleteFile(const std::string& fname);

  /**
   * @brief 创建指定的目录，目录路径为dirname
   *
   * @param dirname 目录路径
   * @return Status 是否成功
   */
  virtual Status CreateDir(const std::string& dirname) = 0;

  /**
   * @brief 删除文件fname，默认实现调用DeleteDir，需要实现Env的子类
   * 请覆写RemoveDir函数，保持DeleteDir的默认实现，最新的代码最好调用
   * RemoveDir函数，而不是调用DeleteDir函数
   *
   * @param dirname 要删除的目录
   * @return Status 是否成功
   */
  virtual Status RemoveDir(const std::string& dirname);

  /**
   * @brief 该方法即将废弃，子类Env覆写RemoveDir函数，使用RemoveDir函数，
   * 不要覆DeleteDir函数，也不要使用DeleteDir函数
   *
   * @param dirname 要删除的目录
   * @return Status 是否成功
   */
  virtual Status DeleteDir(const std::string& dirname);

  /**
   * @brief 获取文件fname的大小，值储存到*file_size里面
   *
   * @param fname 文件路径
   * @param file_size 文件大小
   * @return Status 是否成功
   */
  virtual Status GetFileSize(const std::string& fname, uint64_t* file_size) = 0;

  /**
   * @brief 重命名文件从src到target
   *
   * @param src 源文件
   * @param target 目的文件
   * @return Status 是否成功
   */
  virtual Status RenameFile(const std::string& src,
                            const std::string& target) = 0;

  /**
   * @brief 锁定指定的文件fname，用来防止多个进程同时访问同一个db
   *
   * @param fname 文件路径
   * @param lock 获得的文件锁
   * @return Status 有以下情况
   * 成功的时候：存储一个FileLock对象到*lock表示获得了文件的锁并且返回OK
   * 调用者必须调用UnlockFile(*lock)去释放锁。如果进程退出，文件锁将自动
   * 释放。
   *
   * 失败的时候：将*lock设置为nullptr，并且返回non-OK
   */
  virtual Status LockFile(const std::string& fname, FileLock** lock) = 0;

  /**
   * @brief 释放已经成功通过LockFile获得的锁lock
   * 要求：lock是通过成功调用LockFile得到的
   * 要求：lock没有被释放
   *
   * @param lock 要释放的锁
   * @return Status 是否成功
   */
  virtual Status UnlockFile(FileLock* lock) = 0;

  /**
   * @brief 将(*function)(arg)加入后台线程调度，function可能通过一个
   * 未指定的线程进行执行，多个function加入同一个Env可能会在后台通过不同
   * 的线程同时运行，调用者不能假设后台执行是顺序的。
   *
   * @param function 要调度执行的function
   * @param arg 传入function的参数
   */
  virtual void Schedule(void (*function)(void* arg), void* arg) = 0;

  /**
   * @brief 启动一个新的线程，当线程被调度的时候执行函数function(arg)
   *
   * @param function thread调度执行的函数
   * @param arg 传入function的参数
   */
  virtual void StartThread(void (*function)(void* arg), void* arg) = 0;

  /**
   * @brief *path目录可以用来进行测试，它可能是刚刚创建的，也可能不是。
   * 同一进程的运行之间的目录可能会或可能不会不同，但后续调用将返回相同的目录。
   *
   * @param path
   * @return Status
   */
  virtual Status GetTestDirectory(std::string* path) = 0;

  /**
   * @brief 创建并返回用于存储信息性消息的日志文件。
   *
   * @param fname
   * @param result
   * @return Status
   */
  virtual Status NewLogger(const std::string& fname, Logger** result) = 0;

  /**
   * @brief 返回自某个固定时间点以来的微秒数。仅对计算时间增量有用。
   *
   * @return uint64_t
   */
  virtual uint64_t NowMicros() = 0;

  /**
   * @brief 将线程休眠/延迟指定的微秒数。
   *
   * @param micros
   */
  virtual void SleepForMicroseconds(int micros) = 0;
};

/**
 * @brief 用于顺序读取文件的抽象类
 *
 */
class LEVELDB_EXPORT SequentialFile {
 public:
  SequentialFile() = default;

  SequentialFile(const SequentialFile&) = delete;
  SequentialFile& operator=(const SequentialFile&) = delete;

  virtual ~SequentialFile();

  /**
   * @brief
   * 从文件从读取最多读取n个字节，数据写入scratch[0...n-1]中，并且设置到*result中
   * （包括成功读取小于n个字节），*result中的指针指向scratch中的内存，所以请保证*result在使用
   * 过程中scratch的内存一直存在
   * 要求：外部保证线程间的同步
   *
   * @param n
   * @param result
   * @param scratch
   * @return Status 读取失败返回non-OK，读取成功返回OK
   */
  virtual Status Read(size_t n, Slice* result, char* scratch) = 0;

  /**
   * @brief
   * 从文件的当前位置跳过n个字节，这保证不会比读取相同的n个字节数据慢，但可能会更快。
   * 如果到达文件末尾，则跳过将在文件末尾停止，并且 Skip 将返回 OK。
   * 要求：外部保证线程间的同步
   *
   * @param n
   * @return status
   */
  virtual Status Skip(size_t n) = 0;
};

/**
 * @brief 用于随机读取文件内容的抽象类
 *
 */
class LEVELDB_EXPORT RandomAccessFile {
 public:
  RandomAccessFile() = default;

  RandomAccessFile(const RandomAccessFile&) = delete;
  RandomAccessFile& operator=(const RandomAccessFile&) = delete;

  virtual ~RandomAccessFile();
  /**
   * @brief
   * 从文件的offse读取最多读取n个字节，数据写入scratch[0...n-1]中，并且设置到*result中
   * （包括成功读取小于n个字节），*result中的指针指向scratch中的内存，所以请保证*result在使用
   * 过程中scratch的内存一直存在
   * 要求：外部保证线程间的同步
   *
   * @param offset
   * @param n
   * @param result
   * @param scratch
   * @return Status
   */
  virtual Status Read(uint64_t offset, size_t n, Slice* result, char* scratch) = 0;
};

/**
 * 用于顺序写文件的抽象类。实现者写的时候必须提供buffer，因为可能每次会写入少量数据入文件。
 */
class LEVELDB_EXPORT WritableFile {
public:
  WritableFile() = default;

  WritableFile(const WritableFile&) = delete;
  WritableFile& operator=(const WritableFile&) = delete;

  virtual ~WritableFile();

  /**
   * @brief 向文件中写入数据
   * 
   * @param data 
   * @return Status 
   */
  virtual Status Append(const Slice& data) = 0;

  virtual Status Close() = 0;

  virtual Status Flush() = 0;

  virtual Status Sync() = 0;
};


/**
 * @brief 写日志文件的街口抽象类
 * 
 */
class LEVELDB_EXPORT Logger {
public:
  Logger() = default;

  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  virtual ~Logger();

  /**
   * @brief 将变量以特定格式写入日志文件
   * 
   * @param fotmat 
   * @param ap 
   */
  virtual void LogV(const char* fotmat, std::va_list ap) = 0;
};


/**
 * @brief 标识一个被锁定的文件
 * 
 */
class LEVELDB_EXPORT FileLock {
public:
  FileLock() = default;

  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;

  virtual ~FileLock();
};

/**
 * @brief 如果info_log非空，将指定的数据写入info_log
 * 
 * @param info_log 
 * @param format 
 * @param ... 
 */
void Log(Logger* info_log, const char* format, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((__format__(__printf__, 2, 3)))
#endif
    ;

/**
 * @brief 实用函数：将data写入文件fname
 * 
 * @param env 
 * @param data 
 * @param fname 
 * @return Status 
 */
LEVELDB_EXPORT Status WriteStringToFile(Env* env, const Slice& data, const std::string& fname);

/**
 * @brief 实用函数：将data写入文件fname，并且同步数据到磁盘
 * 
 * @param env 
 * @param data 
 * @param fname 
 * @return LEVELDB_EXPORT 
 */
LEVELDB_EXPORT Status WriteStringToFileSync(Env* env, const Slice& data, const std::string& fname);

/**
 * @brief 实用函数：从文件fname中读取数据到data中
 * 
 * @param env 
 * @param fname 
 * @param data 
 * @return LEVELDB_EXPORT 
 */
LEVELDB_EXPORT Status ReadFileToString(Env* env, const std::string& fname, std::string* data);

// An implementation of Env that forwards all calls to another Env.
// May be useful to clients who wish to override just part of the
// functionality of another Env.
class LEVELDB_EXPORT EnvWrapper : public Env {
 public:
  // Initialize an EnvWrapper that delegates all calls to *t.
  explicit EnvWrapper(Env* t) : target_(t) {}
  virtual ~EnvWrapper();

  // Return the target to which this Env forwards all calls.
  Env* target() const { return target_; }

  // The following text is boilerplate that forwards all methods to target().
  Status NewSequentialFile(const std::string& f, SequentialFile** r) override {
    return target_->NewSequentialFile(f, r);
  }
  Status NewRandomAccessFile(const std::string& f,
                             RandomAccessFile** r) override {
    return target_->NewRandomAccessFile(f, r);
  }
  Status NewWritableFile(const std::string& f, WritableFile** r) override {
    return target_->NewWritableFile(f, r);
  }
  Status NewAppendableFile(const std::string& f, WritableFile** r) override {
    return target_->NewAppendableFile(f, r);
  }
  bool FileExists(const std::string& f) override {
    return target_->FileExists(f);
  }
  Status GetChildren(const std::string& dir,
                     std::vector<std::string>* r) override {
    return target_->GetChildren(dir, r);
  }
  Status RemoveFile(const std::string& f) override {
    return target_->RemoveFile(f);
  }
  Status CreateDir(const std::string& d) override {
    return target_->CreateDir(d);
  }
  Status RemoveDir(const std::string& d) override {
    return target_->RemoveDir(d);
  }
  Status GetFileSize(const std::string& f, uint64_t* s) override {
    return target_->GetFileSize(f, s);
  }
  Status RenameFile(const std::string& s, const std::string& t) override {
    return target_->RenameFile(s, t);
  }
  Status LockFile(const std::string& f, FileLock** l) override {
    return target_->LockFile(f, l);
  }

  Status UnlockFile(FileLock* l) override { return target_->UnlockFile(l); }
  
  void Schedule(void (*f)(void*), void* a) override {
    return target_->Schedule(f, a);
  }
  void StartThread(void (*f)(void*), void* a) override {
    return target_->StartThread(f, a);
  }
  Status GetTestDirectory(std::string* path) override {
    return target_->GetTestDirectory(path);
  }
  Status NewLogger(const std::string& fname, Logger** result) override {
    return target_->NewLogger(fname, result);
  }
  uint64_t NowMicros() override { return target_->NowMicros(); }
  void SleepForMicroseconds(int micros) override {
    target_->SleepForMicroseconds(micros);
  }

 private:
  Env* target_;
};

}  // namespace leveldb

#endif  // STORAGE_LEVELDB_INCLUDE_ENV_H_
