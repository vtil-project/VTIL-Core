<p align="center">

  <a href="https://www.vtil.org/">
    <img width="256" heigth="256" src="https://vtil.org/logo.png">
  </a>  

  <h1 align="center">VTIL</h1>

  <p align="center">
    <a href="https://travis-ci.com/vtil-project/VTIL-Core">
      <img src="https://img.shields.io/travis/vtil-project/vtil-core/master.svg?style=flat-square" alt="travis-ci"/>
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
VTIL Project, Virtual-machine Translation Intermediate Language, is a set of tools that can be used for binary deobfuscation and devirtualization. 

Main difference between VTIL and other optimizing compilers such as LLVM is that it has an extremely versatile IL that makes it trivial to lift from any architecture including stack machines. Since it is built for translation, the IL does not completely abstract away the original ISA and keeps the concept of a stack, physical registers and non-SSA architecture as is. 

Physical registers and stack can be used freely with VTIL instructions while still having infinite temporaries to use during code generation. It is also possible to emit native instructions in the middle of the IL stream.

VTIL also makes it trivial to emit code back into the native format at any virtual address requested without being contrained to a specific file format.

## 2) What is this repostiory?

This repository contains the core components of the VTIL Project used across the VTIL toolchain.

It is currently incomplete as initial release is not done yet, and documentation and FAQ will be within this repository and the organization website once they're done.

Until the initial release you can keep up to date with the VTIL project by checking my [personal twitter account](https://twitter.com/_can1357) or the VTIL website [vtil.org](https://vtil.org/).
