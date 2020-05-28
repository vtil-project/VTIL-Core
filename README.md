<p align="center">

  <a href="https://www.vtil.org/">
    <img width="256" heigth="256" src="https://vtil.org/logo.png">
  </a>  

  <h1 align="center">VTIL</h1>

  <p align="center">
    <a href="https://travis-ci.com/vtil-project/VTIL-Core">
      <img src="https://img.shields.io/travis/com/vtil-project/vtil-core/master.svg?logo=travis&style=flat-square" alt="travis-ci"/>
    </a>
    <a href="https://ci.appveyor.com/project/can1357/vtil-core">
      <img src="https://img.shields.io/appveyor/build/can1357/VTIL-Core?logo=appveyor&style=flat-square" alt="appveyor-ci"/>
    </a>
    <a href="https://github.com/vtil-project/vtil-core/blob/master/LICENSE.md">
      <img src="https://img.shields.io/github/license/vtil-project/vtil-core.svg?style=flat-square" alt="license"/>
    </a>
  </p>

  <p align="center">
    Virtual-machine Translation Intermediate Language
  </p>
</p>

# Introduction

## 1) What is VTIL?

VTIL Project, standing for Virtual-machine Translation Intermediate Language, is a set of tools designed around an optimizing compiler to be used for binary de-obfuscation and de-virtualization.

The main difference between VTIL and other optimizing compilers such as LLVM is that it has an extremely versatile IL that makes it trivial to lift from any architecture including stack machines. Since it is built for translation, VTIL does not abstract away the native ISA and keeps the concept of the stack, physical registers, and the non-SSA architecture of a general-purpose CPU as is. Native instructions can be emitted in the middle of the IL stream and the physical registers can be addressed from VTIL instructions freely.

VTIL also makes it trivial to emit code back into the native format at any virtual address requested without being constrained to a specific file format.

## 2) What is this repository?

This repository contains the core components of the VTIL Project used across the toolchain.

It is currently incomplete as the initial release is not done yet, and documentation and FAQ will be within this repository and the organization website once they're done.

Until the initial release, you can keep up to date with the VTIL project by checking my [personal twitter account](https://twitter.com/_can1357) or the VTIL website [vtil.org](https://vtil.org/).
