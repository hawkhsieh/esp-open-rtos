# Component makefile for binary SDK components

binary_sdk_SRC_DIR =  $(ROOT)binary_sdk/libmain $(ROOT)binary_sdk/libnet80211 $(ROOT)binary_sdk/libphy $(ROOT)binary_sdk/libpp $(ROOT)binary_sdk/libwpa

$(eval $(call component_compile_rules,binary_sdk))
