// Defines utility allowing files for bitcode output wrapping.

#ifndef FILE_WRAPPER_OUTPUT_H__
#define FILE_WRAPPER_OUTPUT_H__

#include <stdio.h>

#include "llvm/Support/support_macros.h"
#include "llvm/Wrap/wrapper_output.h"

// Define a class to wrap named files. */
class FileWrapperOutput : public WrapperOutput {
 public:
  FileWrapperOutput(const char* name);
  ~FileWrapperOutput();
  // Writes a single byte, returning false if unable to write.
  virtual bool Write(uint8_t byte);
  // Writes the specified number of bytes in the buffer to
  // output. Returns false if unable to write.
  virtual bool Write(const uint8_t* buffer, size_t buffer_size);
 private:
  // The name of the file
  const char* _name;
  // The corresponding (opened) file.
  FILE* _file;
 private:
  DISALLOW_CLASS_COPY_AND_ASSIGN(FileWrapperOutput);
};
#endif  // FILE_WRAPPER_OUTPUT_H__
