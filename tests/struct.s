BITS 64;
;typedef struct node {
;    int data;
;    node* next;
;    node* prev;
;    int empty;
;};

;void function(node* n, int a) {
;    node* curr = n;
;    while (!(curr -> empty)) {
;        if (curr -> data % 2 == 0){
;            curr = curr -> next;
;        } else {
;            curr = curr -> prev;
;        }
;    }
    
;    curr -> data = a;
;    return;
;}


function:
        jmp     .L7
.L4:
        mov     rax, QWORD [rdi+8]
        test    BYTE [rdi], 1
        cmovne  rax, QWORD [rdi+16]
        mov     rdi, rax
.L7:
        mov     eax, DWORD [rdi+24]
        test    eax, eax
        je      .L4
        mov     DWORD [rdi], esi
