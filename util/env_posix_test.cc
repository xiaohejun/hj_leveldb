
#include "gtest/gtest.h"
#include "leveldb/env.h"
#include "util/test_util.h"
#include "util/env_posix_test_helper.h"

namespace leveldb {

static const int kReadOnlyFileLimit = 4;
static const int kMMapLimit = 4;

class EnvPosixTest : public testing::Test {
public:
    Env* env_;

    EnvPosixTest() : env_(Env::Defalut()) {}
    
    static void SetFileLimits(int read_only_file_limit, int mmap_limit) {
        EnvPosixTestHelper::SetReadOnlyFdLimit(read_only_file_limit);
        EnvPosixTestHelper::SetReadOnlyMMapLimit(mmap_limit);
    }
};

TEST_F(EnvPosixTest, TestOpenOnRead)
{
    // open a file
    std::string test_dir;
    ASSERT_LEVELDB_OK(env_->GetTestDirectory(&test_dir));
    std::string test_file = test_dir + "open_on_read.txt";

    // write data to file
    FILE* f = std::fopen(test_file.c_str(), "we");
    ASSERT_TRUE(f != nullptr);
    const char kFileData[] = "abcdefghijklmnopqrstuvwxyz";
    fputs(kFileData, f);
    std::fclose(f);

    // open file by random access
    const int kNumFiles = kReadOnlyFileLimit + kMMapLimit + 5;
    leveldb::RandomAccessFile* files[kNumFiles] = {nullptr};
    for (int i = 0; i < kNumFiles; ++i) {
        ASSERT_LEVELDB_OK(env_->NewRandomAccessFile(test_file, &files[i]));
    }

    // read data
    char scratch;
    Slice result;
    for (int i = 0; i < kNumFiles; ++i) {
        ASSERT_LEVELDB_OK(files[i]->Read(i, 1, &result, &scratch));
        ASSERT_EQ(result[0], kFileData[i]);
    }

    // delete file
    for (int i = 0; i < kNumFiles; ++i) {
        delete files[i];
    }

    // remove file
    ASSERT_LEVELDB_OK(env_->RemoveFile(test_file));
    ASSERT_FALSE(env_->FileExists(test_file));
}

}; // namespace leveldb

int main(int argc, char** argv)
{
    // 所有的测试用例在同一个设置read-only limit下运行
    leveldb::EnvPosixTest::SetFileLimits(leveldb::kReadOnlyFileLimit, leveldb::kMMapLimit);
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
