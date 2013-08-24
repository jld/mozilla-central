/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * This is an implementation of stack unwinding according to a subset
 * of the ARM Exception Handling ABI, as described in:
 *   http://infocenter.arm.com/help/topic/com.arm.doc.ihi0038a/IHI0038A_ehabi.pdf
 */

#ifndef mozilla_EHABIStackWalk_h__
#define mozilla_EHABIStackWalk_h__

#include <stdint.h>
#include <vector>
#include <string>

#ifdef ANDROID
# include "android-signal-defs.h"
#else
# include <ucontext.h>
#endif

#include "mozilla/Atomics.h"

namespace mozilla {
namespace ehabi {

struct Entry;

class State {
public:
  // Note that any core register can be used as a "frame pointer" to
  // influence the unwinding process, so this must track all of them.
  uint32_t mRegs[16];
  bool unwind(const Entry *aEntry, const void *stackBase);
  uint32_t &operator[](int i) { return mRegs[i]; }
  const uint32_t &operator[](int i) const { return mRegs[i]; }
  State(const mcontext_t &);
};

enum {
  R_SP = 13,
  R_LR = 14,
  R_PC = 15
};

struct EntryHandle {
  const Entry *mValue;
  EntryHandle(const Entry *aEntry) : mValue(aEntry) { }
};

struct Table {
  uint32_t mStartPC;
  uint32_t mEndPC;
  uint32_t mLoadOffset;
  // In principle we should be able to binary-search the index section in
  // place, but the ICS toolchain's linker is noncompliant and produces
  // indices that aren't entirely sorted (e.g., libc).  So we have this:
  std::vector<EntryHandle> mEntries;
  std::string mName;

  Table(const void *aELF, size_t aSize, const std::string &aName);
  const Entry *lookup(uint32_t aPC) const;
  operator bool() const { return mEntries.size() > 0; }
  const std::string &name() const { return mName; }
  uint32_t loadOffset() const { return mLoadOffset; }
};

class AddrSpace {
  std::vector<uint32_t> mStarts;
  std::vector<Table> mTables;
  static mozilla::Atomic<const AddrSpace*> sCurrent;
public:
  explicit AddrSpace(const std::vector<Table>& aTables);
  const Table *lookup(uint32_t aPC) const;
  static const AddrSpace *Current(bool aSignalContext);
};

}
}

#endif
