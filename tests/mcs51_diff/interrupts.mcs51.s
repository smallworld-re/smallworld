; Interrupts: when the 8051 takes them, in what order, and what returns.
;
; Main code only counts in R7, one instruction at a time; each handler
; numbers itself in R6 and records R6 and R7 in its own two bytes of
; internal RAM, so the final state shows the order the handlers ran in and
; how far main had got each time.  Requests are made by setting the flags
; in software, which the hardware allows, so no timer or pin is involved.
;
; Handler slots: ext0 0x40, tim0 0x42, ext1 0x44, tim1 0x46, ser 0x48,
; tim2 0x4A.  ext1 also records R6 after the interrupt it nests at 0x4C.

	.area VECT (ABS)
	.org	0x0003
	ljmp	ext0
	.org	0x000B
	ljmp	tim0
	.org	0x0013
	ljmp	ext1
	.org	0x001B
	ljmp	tim1
	.org	0x0023
	ljmp	ser
	.org	0x002B
	ljmp	tim2

	.org	0x0040
ext0:
	inc	r6
	mov	0x40, r6
	mov	0x41, r7
	reti
tim0:
	inc	r6
	mov	0x42, r6
	mov	0x43, r7
	reti
ext1:
	; Low priority.  Switches register banks as a __using(1) handler
	; does, then requests a low-priority interrupt, which must wait for
	; RETI, and a high-priority one, which nests at once.
	inc	r6
	mov	0x44, r6
	mov	0x45, r7
	push	psw
	mov	psw, #0x08
	mov	r1, #0x5A
	pop	psw
	setb	0x8D		; TF0
	setb	0x8F		; TF1
	mov	0x4C, r6
	reti
tim1:
	inc	r6
	mov	0x46, r6
	mov	0x47, r7
	reti
ser:
	; RI and TI are the handler's to clear.
	inc	r6
	mov	0x48, r6
	mov	0x49, r7
	anl	0x98, #0xFC
	reti
tim2:
	; Returns with RET, not RETI, so stays in service.
	inc	r6
	mov	0x4A, r6
	mov	0x4B, r7
	clr	0xCF		; TF2
	ret

	.area CSEG (CODE)
	mov	r6, #0
	mov	r7, #0
	mov	0xB8, #0x00	; IP: all low
	mov	0xA8, #0x00	; IE: all off

	; A request while disabled waits.  Enabling it writes IE, so one more
	; instruction runs before tim0.
	setb	0x8D		; TF0
	inc	r7
	mov	0xA8, #0x82	; EA | ET0
	inc	r7
	inc	r7

	; Taken right after the instruction that requests it.
	mov	0xA8, #0x8F	; EA | ET1 | EX1 | ET0 | EX0
	inc	r7
	setb	0x89		; IE0
	inc	r7

	; Two requests at the same level: polling order picks IE0 first, and
	; after its RETI one more instruction runs before tim1.
	clr	0xAF		; EA
	setb	0x8F		; TF1
	setb	0x89		; IE0
	setb	0xAF		; EA
	inc	r7
	inc	r7
	inc	r7

	; The same with IE0 at high priority: after its RETI, too, one more
	; instruction runs before tim1.  (A high-priority request beating one
	; earlier in polling order is left out: ucsim takes the earlier one
	; first, then lets the other nest at once, where the 8051 manual has
	; the CPU take the higher priority first.)
	clr	0xAF
	setb	0x89		; IE0
	setb	0x8F		; TF1
	mov	0xB8, #0x01	; IP: PX0
	setb	0xAF
	inc	r7
	inc	r7
	inc	r7

	; Nesting: see ext1.
	mov	0xB8, #0x08	; IP: PT1
	setb	0x8B		; IE1
	inc	r7
	inc	r7

	; The serial port and timer 2, on the 8052.
	mov	0xA8, #0xB0	; EA | ET2 | ES
	inc	r7
	setb	0x98		; RI
	inc	r7
	setb	0x99		; TI
	inc	r7

	; A handler that returns with RET stays in service, so a request at
	; its level then waits.
	mov	0xA8, #0xA2	; EA | ET2 | ET0
	inc	r7
	setb	0xCF		; TF2
	inc	r7
	setb	0x8D		; TF0
	inc	r7
	inc	r7
	nop
