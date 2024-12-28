#ifndef STORAGE_LEVELDB_UTIL_TESTUTIL_H_
#define STORAGE_LEVELDB_UTIL_TESTUTIL_H_

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace leveldb {
namespace test {
    
MATCHER(IsOK, "") { return arg.ok(); }

#define EXPECT_LEVELDB_OK(expression) \
    EXPECT_THAT(expression, leveldb::test::IsOK())

#define ASSERT_LEVELDB_OK(expression) \
    ASSERT_THAT(expression, leveldb::test::IsOK())

} // namespace test
} // namespace leveldb



#endif // STORAGE_LEVELDB_UTIL_TESTUTIL_H_