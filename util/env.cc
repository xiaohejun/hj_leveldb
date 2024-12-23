#include "leveldb/env.h"

namespace leveldb
{

Env::Env() = default;

Env::~Env() = default;

Status Env::NewAppendableFile(const std::string& fname, WritableFile** result)
{
    return Status::NotSupported("NewAppendableFile", fname);
}

Status Env::RemoveFile(const std::string& fname)
{
    return DeleteFile(fname);
}

Status Env::DeleteFile(const std::string& fname)
{
    return RemoveFile(fname);
}

Status Env::RemoveDir(const std::string& dirname)
{
    return DeleteDir(dirname);
}

Status Env::DeleteDir(const std::string& dirname)
{
    return RemoveDir(dirname);
}

SequentialFile::~SequentialFile() = default;

RandomAccessFile::~RandomAccessFile() = default;

WritableFile::~WritableFile() = default;

Logger::~Logger() = default;

FileLock::~FileLock() = default;

void Log(Logger* info_log, const char* format, ...)
{
    if (info_log != nullptr) {
        std::va_list ap;
        va_start(ap, format);
        info_log->LogV(format, ap);
        va_end(ap);
    }
}

static Status DoWriteStringToFile(Env* env, const Slice&data, const std::string& fname, bool should_sync)
{
    WritableFile *file = nullptr;
    auto s = env->NewWritableFile(fname, &file);
    if (!s.ok()) {
        return s;
    }
    s = file->Append(data);
    if (s.ok() && should_sync) {
        s = file->Sync();
    }
    if (s.ok()) {
        s = file->Close();
    }
    // 如果上面的操作没有关闭文件，在这里关闭
    delete file; 
    if (!s.ok()) {
        env->RemoveFile(fname);
    }
    return s;
}

Status WriteStringToFile(Env* env, const Slice& data, const std::string& fname)
{
    DoWriteStringToFile(env, data, fname, false);
}

Status WriteStringToFileSync(Env* env, const Slice& data, const std::string& fname)
{
    DoWriteStringToFile(env, data, fname, true);
}

Status ReadFileToString(Env* env, const std::string& fname, std::string* data)
{
    data->clear();
    SequentialFile *file;
    auto s = env->NewSequentialFile(fname, &file);
    if (!s.ok()) {
        return s;
    }
    const size_t kBufferSize = 8 * 1024;
    char* buffer = new char[kBufferSize];
    Slice result;
    while (true) {
        s = file->Read(kBufferSize, &result, buffer);
        if (!s.ok()) {
            break;
        }
        if (result.empty()) {
            break;
        }
        data->append(result.data(), result.size());
    }
    delete[] buffer;
    delete file;
    return s;
}

EnvWrapper::~EnvWrapper() = default;
    
} // namespace leveldb