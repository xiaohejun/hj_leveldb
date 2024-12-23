#ifndef STORAGE_LEVELDB_UTIL_ENV_POSIX_TEST_HELPER_H_
#define STORAGE_LEVELDB_UTIL_ENV_POSIX_TEST_HELPER_H_

namespace leveldb {

class EnvPosixTest;

class EnvPosixTestHelper {
private:
    friend class EnvPosixTest;

    static void SetReadOnlyFdLimit(int limit);

    static void SetReadOnlyMMapLimit(int limit);
};

};

#endif // STORAGE_LEVELDB_UTIL_ENV_POSIX_TEST_HELPER_H_