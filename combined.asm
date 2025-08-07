;==============================
; Full Test (no .sect, no .word)
; Includes .bss, .data, .text labels
;==============================

.DEFINE SIZE 4
.EQU MASK 0xFF
.ASG 0xC000, RESET

;==============================
; TEXT (CODE) SEGMENT
;==============================
.ORG 0xC000  ; .text section start

TEXT_START:         ; simulate .text label

    MOV.W   #DATA_START, R4     ; pointer to data
    MOV.W   #BUFFER, R5         ; pointer to bss buffer
    MOV.W   #SIZE, R6           ; loop counter

LOOP:
    MOV.B   @R4+, R7            ; load byte from data
    AND.B   #MASK, R7           ; apply mask
    MOV.B   R7, 0(R5)           ; store result to bss
    INC     R5                  ; move to next byte
    DEC     R6
    JNZ     LOOP                ; repeat

    JMP     DONE

;==============================
; MACRO
;==============================
MACRO CLEAR_REGS
    CLR.W   R4
    CLR.W   R5
    CLR.W   R6
ENDM

    CLEAR_REGS

DONE:
    NOP                         ; end of program


;==============================
; DATA SEGMENT
;==============================
.ORG 0xD000  ; .data section start

DATA_START:           ; simulate .data label
    .BYTE   0x12, 0x34, 0xAB, 0xCD
    .ASCII  "OK"
    .STRINGZ "Done!"

;==============================
; BSS SEGMENT (Uninitialized)
;==============================
.ORG 0xE000  ; .bss section start

BUFFER:               ; simulate .bss label
    .BYTE   0, 0, 0, 0           ; reserve SIZE bytes.DEF START_VALUE
START_VALUE .SET 0x0009