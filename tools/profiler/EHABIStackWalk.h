/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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

namespace mozilla {
namespace ehabi {

struct Entry;

class State {
public:
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

struct Table {
  uint32_t mStartPC;
  uint32_t mEndPC;
  uint32_t mLoadOffset;
  const void *mStartTable;
  const void *mEndTable;
  std::string mName;

  Table(const void *aELF, size_t aSize, const std::string &aName);
  const Entry *lookup(uint32_t aPC) const;
  operator bool() const { return mStartTable; }
};

class AddrSpace {
  std::vector<uint32_t> mStarts;
  std::vector<Table> mTables;
public:
  explicit AddrSpace(const std::vector<Table>& aTables);
  const Table *lookup(uint32_t aPC) const;
  static const AddrSpace *Current();
};

}
}

#endif
