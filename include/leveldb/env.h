#ifndef STORAGE_LEVELDB_INCLUDE_ENV_H_
#define STORAGE_LEVELDB_INCLUDE_ENV_H_

namespace leveldb {

#include <string>
#include <vector>

#include "leveldb/export.h"
#include "leveldb/status.h"

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
  static Env* Defalut();

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
  virtual Status NewSequentialFile(const std::string& fname, SequentialFile** result) = 0;

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
  virtual Status NewRandomAccessFile(const std::string& fname, RandomAccessFile** result) = 0;

  /**
   * @brief 创建一个WritableFile对象可用于写文件，文件路径是fname，如果fname文件存在，则先删除该文件
   * 返回的文件同一时间只能由一个线程进行访问
   * 
   * @param fname 文件路径名
   * @param result 存储一个WritableFile对象指针到*result中
   * @return Status 返回结果有以下情况
   * 成功的时候：返回OK，并且设置*result的值为一个WritableFile对象
   * 失败的时候：返回OK之外的值，*result设置为nullptr
   */
  virtual Status NewWritableFile(const std::string& fname, WritableFile** result) = 0;

  /**
   * @brief 创建一个WritableFile对象用于在一个已经存在的文件fname后面继续写，如果文件不存在，则创建
   * 并且从头开始写，返回的文件同一时间只能由一个线程进行访问
   * 
   * @param fname 文件路径
   * @param result 存储一个WritableFile对象到指针*result中
   * @return Status  返回结果有以下情况
   * 成功的时候：返回OK，并且设置*result的值为一个WritableFile对象
   * 失败的时候：返回OK之外的值，*result设置为nullptr
   */
  virtual Status NewAppendableFile(const std::string& fname, WritableFile** result);

  /**
   * @brief 检查文件是否存在
   * 
   * @param fname 文件路径
   * @return true 文件fname存在
   * @return false 文件fname不存在
   */
  virtual bool FileExists(const std::string& fname) = 0;

  /**
   * @brief 首先清空*result中的内容，获取dir目录中所有的文件名存储到*result中，文件名的路径相对于dir
   * 
   * @param dir 目录
   * @param result dir下的所有文件，第一层
   * @return Status 是否成功
   */
  virtual Status GetChildren(const std::string& dir, std::vector<std::string>* result) = 0;

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
  virtual Status GetFileSize(const std::string& fname, uint64_t* file_size);

  /**
   * @brief 重命名文件从src到target
   * 
   * @param src 源文件
   * @param target 目的文件
   * @return Status 是否成功
   */
  virtual Status RenameFile(const std::string& src, const std::string &target) = 0;

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
  virtual Status UnLockFile(FileLock *lock);

  /**
   * @brief 将(*function)(arg)加入后台线程调度，function可能通过一个
   * 未指定的线程进行执行，多个function加入同一个Env可能会在后台通过不同
   * 的线程同时运行，调用者不能假设后台执行是顺序的。
   * 
   * @param function 要调度执行的function
   * @param arg 传入function的参数
   */
  virtual void Schedule(void (*function)(void* arg), void *arg) = 0;

  /**
   * @brief 启动一个新的线程，当线程被调度的时候执行函数function(arg)
   * 
   * @param function thread调度执行的函数
   * @param arg 传入function的参数
   */
  virtual void StartThread(void (*function)(void* arg), void *arg) = 0l

  /**
   * @brief *path目录可以用来进行测试，它可能是刚刚创建的，也可能不是。
   * 同一进程的运行之间的目录可能会或可能不会不同，但后续调用将返回相同的目录。
   * 
   * @param path 
   * @return Status 
   */
  virtual Status GetTestDirectory(std:string* path) = 0;

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
   * @brief 从文件从读取最多读取n个字节，数据写入scratch[0...n-1]中，并且设置到*result中
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
   * @brief 从文件的当前位置跳过n个字节，这保证不会比读取相同的n个字节数据慢，但可能会更快。
   * 如果到达文件末尾，则跳过将在文件末尾停止，并且 Skip 将返回 OK。
   * 要求：外部保证线程间的同步
   * 
   * @param n 
   * @return status 
   */
  virtual status Skip(size_t n) = 0;
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
   * @brief 从文件的offse读取最多读取n个字节，数据写入scratch[0...n-1]中，并且设置到*result中
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
  virtual Status Read(uint64_t offset, size_t n, Slice* result, char* scratch);
};




}  // namespace leveldb

#endif  // STORAGE_LEVELDB_INCLUDE_ENV_H_
