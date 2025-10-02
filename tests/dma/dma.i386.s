    .text
divide:
    mov $0x50014000,%edx
    mov %edi,(%edx)
    mov %esi,0x4(%edx)
    mov 0x8(%edx),%eax
    nop
