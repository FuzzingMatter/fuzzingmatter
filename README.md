# Getting started

#### Linux
```bash
git submodule update --init --recursive
source scripts/bootstrap.sh
source scripts/activate.sh
./scripts/build/build_examples.py --target linux-x64-chip-tool-clang --quiet build
./scripts/build/build_examples.py --target linux-x64-all-clusters-clang --quiet build
```

#### MacOS
```bash
git submodule update --init --recursive
source scripts/bootstrap.sh
source scripts/activate.sh
./scripts/build/build_examples.py --target darwin-arm64-chip-tool-clang --quiet build
./scripts/build/build_examples.py --target darwin-arm64-all-clusters-clang --quiet build
```
