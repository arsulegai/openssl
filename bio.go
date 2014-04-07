// Copyright (C) 2014 Space Monkey, Inc.
// +build cgo

package openssl

/*
#include <string.h>
#include <openssl/bio.h>

extern int cbioNew(BIO *b);
extern int cbioFree(BIO *b);

extern int writeBioWrite(BIO *b, char *buf, int size);
extern long writeBioCtrl(BIO *b, int cmd, long arg1, void *arg2);
static int writeBioPuts(BIO *b, const char *str) {
    return writeBioWrite(b, (char*)str, (int)strlen(str));
}

extern int readBioRead(BIO *b, char *buf, int size);
extern long readBioCtrl(BIO *b, int cmd, long arg1, void *arg2);

static BIO_METHOD writeBioMethod = {
    BIO_TYPE_SOURCE_SINK,
    "Go Write BIO",
    (int (*)(BIO *, const char *, int))writeBioWrite,
    NULL,
    writeBioPuts,
    NULL,
    writeBioCtrl,
    cbioNew,
    cbioFree,
    NULL};

static BIO_METHOD* BIO_s_writeBio() { return &writeBioMethod; }

static BIO_METHOD readBioMethod = {
    BIO_TYPE_SOURCE_SINK,
    "Go Read BIO",
    NULL,
    readBioRead,
    NULL,
    NULL,
    readBioCtrl,
    cbioNew,
    cbioFree,
    NULL};

static BIO_METHOD* BIO_s_readBio() { return &readBioMethod; }

static void BIO_clear_retry_flags_not_a_macro(BIO *b) {
    BIO_clear_retry_flags(b);
}

static void BIO_set_retry_read_not_a_macro(BIO *b) { BIO_set_retry_read(b); }
*/
import "C"

import (
	"errors"
	"io"
	"reflect"
	"sync"
	"unsafe"
)

const (
	SSLRecordSize = 16 * 1024
)

func nonCopyGoBytes(ptr uintptr, length int) []byte {
	var slice []byte
	header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	header.Cap = length
	header.Len = length
	header.Data = ptr
	return slice
}

func nonCopyCString(data *C.char, size C.int) []byte {
	return nonCopyGoBytes(uintptr(unsafe.Pointer(data)), int(size))
}

//export cbioNew
func cbioNew(b *C.BIO) C.int {
	b.shutdown = 1
	b.init = 1
	b.num = -1
	b.ptr = nil
	b.flags = 0
	return 1
}

//export cbioFree
func cbioFree(b *C.BIO) C.int {
	return 1
}

type writeBio struct {
	data_mtx sync.Mutex
	op_mtx   sync.Mutex
	buf      []byte
}

func loadWritePtr(b *C.BIO) *writeBio {
	return (*writeBio)(unsafe.Pointer(b.ptr))
}

//export writeBioWrite
func writeBioWrite(b *C.BIO, data *C.char, size C.int) (rc C.int) {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: writeBioWrite panic'd: %v", err)
			rc = -1
		}
	}()
	ptr := loadWritePtr(b)
	if ptr == nil || data == nil || size < 0 {
		return -1
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	C.BIO_clear_retry_flags_not_a_macro(b)
	ptr.buf = append(ptr.buf, nonCopyCString(data, size)...)
	return size
}

//export writeBioCtrl
func writeBioCtrl(b *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) (
	rc C.long) {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: writeBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_WPENDING:
		return writeBioPending(b)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		return 1
	default:
		return 0
	}
}

func writeBioPending(b *C.BIO) C.long {
	ptr := loadWritePtr(b)
	if ptr == nil {
		return 0
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	return C.long(len(ptr.buf))
}

func (b *writeBio) WriteTo(w io.Writer) (rv int64, err error) {
	b.op_mtx.Lock()
	defer b.op_mtx.Unlock()

	// write whatever data we currently have
	b.data_mtx.Lock()
	data := b.buf
	b.data_mtx.Unlock()

	if len(data) == 0 {
		return 0, nil
	}
	n, err := w.Write(data)

	// subtract however much data we wrote from the buffer
	b.data_mtx.Lock()
	b.buf = b.buf[:copy(b.buf, b.buf[n:])]
	b.data_mtx.Unlock()

	return int64(n), err
}

func (self *writeBio) Disconnect(b *C.BIO) {
	if loadWritePtr(b) == self {
		b.ptr = nil
	}
}

func (b *writeBio) MakeCBIO() *C.BIO {
	rv := C.BIO_new(C.BIO_s_writeBio())
	rv.ptr = unsafe.Pointer(b)
	return rv
}

type readBio struct {
	data_mtx sync.Mutex
	op_mtx   sync.Mutex
	buf      []byte
	eof      bool
}

func loadReadPtr(b *C.BIO) *readBio {
	return (*readBio)(unsafe.Pointer(b.ptr))
}

//export readBioRead
func readBioRead(b *C.BIO, data *C.char, size C.int) (rc C.int) {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: readBioRead panic'd: %v", err)
			rc = -1
		}
	}()
	ptr := loadReadPtr(b)
	if ptr == nil || size < 0 {
		return -1
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	C.BIO_clear_retry_flags_not_a_macro(b)
	if len(ptr.buf) == 0 {
		if ptr.eof {
			return 0
		}
		C.BIO_set_retry_read_not_a_macro(b)
		return -1
	}
	if size == 0 || data == nil {
		return C.int(len(ptr.buf))
	}
	n := copy(nonCopyCString(data, size), ptr.buf)
	ptr.buf = ptr.buf[:copy(ptr.buf, ptr.buf[n:])]
	return C.int(n)
}

//export readBioCtrl
func readBioCtrl(b *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) (
	rc C.long) {

	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: readBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_PENDING:
		return readBioPending(b)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		return 1
	default:
		return 0
	}
}

func readBioPending(b *C.BIO) C.long {
	ptr := loadReadPtr(b)
	if ptr == nil {
		return 0
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	return C.long(len(ptr.buf))
}

func (b *readBio) ReadFromOnce(r io.Reader) (n int, err error) {
	b.op_mtx.Lock()
	defer b.op_mtx.Unlock()

	// make sure we have a destination that fits at least one SSL record
	b.data_mtx.Lock()
	if cap(b.buf) < len(b.buf)+SSLRecordSize {
		new_buf := make([]byte, len(b.buf), len(b.buf)+SSLRecordSize)
		copy(new_buf, b.buf)
		b.buf = new_buf
	}
	dst := b.buf[len(b.buf):cap(b.buf)]
	dst_slice := b.buf
	b.data_mtx.Unlock()

	n, err = r.Read(dst)
	b.data_mtx.Lock()
	defer b.data_mtx.Unlock()
	if n > 0 {
		if len(dst_slice) != len(b.buf) {
			// someone shrunk the buffer, so we read in too far ahead and we
			// need to slide backwards
			copy(b.buf[len(b.buf):len(b.buf)+n], dst)
		}
		b.buf = b.buf[:len(b.buf)+n]
	}
	return n, err
}

func (b *readBio) MakeCBIO() *C.BIO {
	rv := C.BIO_new(C.BIO_s_readBio())
	rv.ptr = unsafe.Pointer(b)
	return rv
}

func (self *readBio) Disconnect(b *C.BIO) {
	if loadReadPtr(b) == self {
		b.ptr = nil
	}
}

func (b *readBio) MarkEOF() {
	b.data_mtx.Lock()
	defer b.data_mtx.Unlock()
	b.eof = true
}

type anyBio C.BIO

func asAnyBio(b *C.BIO) *anyBio { return (*anyBio)(b) }

func (b *anyBio) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n = int(C.BIO_read((*C.BIO)(b), unsafe.Pointer(&buf[0]), C.int(len(buf))))
	if n <= 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (b *anyBio) Write(buf []byte) (written int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.BIO_write((*C.BIO)(b), unsafe.Pointer(&buf[0]),
		C.int(len(buf))))
	if n != len(buf) {
		return n, errors.New("BIO write failed")
	}
	return n, nil
}
