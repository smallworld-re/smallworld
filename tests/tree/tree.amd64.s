BITS 64;
;typedef struct node {
;    int data;
;    node *lo;
;    node *hi;
;};

;int contains(node *n, int a) {
;    node *curr = n;
;    while(1) {
;        if(curr->data == a) {
;            return 1;
;        } else if(curr->data < a) {
;            if(curr->hi == NULL) {
;                return 0;
;            }
;            curr = curr->hi;
;        } else {
;            if(curr->lo == NULL) {
;                return 0;
;            }
;            curr = curr->lo;
;        }
;    }
;}

.LOOP:
    mov     eax, DWORD[rdi]     ; Load curr->data
    cmp     esi, eax            ; Compare curr->data and a (Did I get this right?)
    je      .PASS               ; If equal, pass 
    jg      .HI                 ; If greater, goto greater
.LO:
    mov     rax, QWORD[rdi+8]   ; Load curr->lo
    jmp     .NULL
.HI:
    mov     rax, QWORD[rdi+16]  ; Load curr->hi
    jmp     .NULL               ; Yes, this is silly, but it makes the blocks pretty
.NULL:
    cmp     rax, $0             ; Check if the next node is NULL
    je      .FAIL               ; If it is, fail
    mov     rdi, rax            ; Move next into curr
    jmp     .LOOP               ; Continue loop
.PASS:
    mov     eax, $1
    ret
.FAIL:
    mov     eax, $0
    ret
