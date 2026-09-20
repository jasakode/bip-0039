.PHONY: build clean

NAME := bip0039
BUILD_DIR := share
LIB := $(BUILD_DIR)/lib$(NAME).so
HEADER := $(BUILD_DIR)/lib$(NAME).h

ifeq ($(shell uname -s),Darwin)
SED_INPLACE := sed -i ''
else
SED_INPLACE := sed -i
endif

build:
	mkdir -p $(BUILD_DIR)

	go build \
		-buildmode=c-shared \
		-o $(LIB) \
		share/main.go

	$(SED_INPLACE) \
		's/GO_CGO_EXPORT_PROLOGUE_H/JASAKODE_BIP0039_EXPORT_H/g' \
		$(HEADER)

clean:
	rm -rf $(BUILD_DIR)