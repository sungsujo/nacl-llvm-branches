#include <sys/stat.h>
#include <stdlib.h>

#include "llvm/Wrap/file_wrapper_input.h"

FileWrapperInput::FileWrapperInput(const char* name) :
    _name(name), _at_eof(false), _size_found(false), _size(0) {
  _file = fopen(name, "rb");
  if (NULL == _file) {
    fprintf(stderr, "Unable to open: %s\n", name);
    exit(1);
  }
}

FileWrapperInput::~FileWrapperInput() {
  fclose(_file);
}

size_t FileWrapperInput::Read(uint8_t* buffer, size_t wanted) {
  size_t found = fread((char*) buffer, 1, wanted, _file);
  if (feof(_file) || ferror(_file)) {
    _at_eof = true;
  }
  return found;
}

bool FileWrapperInput::AtEof() {
  return _at_eof;
}

off_t FileWrapperInput::Size() {
  if (_size_found) return _size;
  struct stat st;
  if (0 == stat(_name, &st)) {
    _size_found = true;
    _size = st.st_size;
    return _size;
  } else {
    fprintf(stderr, "Unable to compute file size: %s\n", _name);
    exit(1);
  }
  // NOT REACHABLE.
  return 0;
}

bool FileWrapperInput::Seek(uint32_t pos) {
  return 0 == fseek(_file, (long) pos, SEEK_SET);
}
