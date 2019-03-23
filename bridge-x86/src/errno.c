#include <errno.h>

extern void set_errno(int value)
{
  errno = value;
}