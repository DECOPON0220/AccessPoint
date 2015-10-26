#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

extern int DebugOut;

int DebugPrintf(char *fmt,...)
{
  if(DebugOut){
    va_list	args;

    va_start(args,fmt);
    vfprintf(stderr,fmt,args);
    va_end(args);
  }

  return(0);
}

int DebugPerror(char *msg)
{
  if(DebugOut){
    fprintf(stderr,"%s : %s\n",msg,strerror(errno));
  }

  return(0);
}
