import sys
import capstone
from unicorn import unicorn_const as uc
from unicorn import x86_const as uc_x86
from .exceptions import EmulationError, ConfigurationError

class UnicornEmulationError(EmulationError):

    def __init__(self, exception: Exception, insn : capstone.CsInsn, pc : int, data: list):
        self.exception = exception 
        self.instruction = insn
        self.pc = pc
        self.data = data
        self.type_str = self.get_type_str()
        self.addr = self.get_address()


    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(Attempting to {self.type_str} at {self.exception})"
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}(Attempting to {self.type_str} at {hex(self.addr)})"

    def get_address(self) -> int:
        if 'MEM' in self.data:
            for p in self.data['MEM']:
                addr += self.data['MEM'][p]
        elif 'REG' in self.data:
            print(self.data)
            for p in self.data['REG']:
                addr = self.data['REG'][p]
        elif 'IMM' in self.data:
            addr = self.data['IMM']
        return addr

    def get_type_str(self) -> str:
        print(self.exception)
        if self.exception == uc.UC_ERR_READ_UNMAPPED: 
            type_str = "read unmapped address"
        elif self.exception == uc.UC_ERR_WRITE_UNMAPPED: 
            type_str = "write unmapped address"
        elif self.exception == uc.UC_ERR_FETCH_UNMAPPED: 
            type_str = "read unmapped address"
        elif self.exception == uc.UC_ERR_INSN_INVALID: 
            type_str = "read invalid bytes"

        return type_str 


# TODO
class UnicornConfigurationError(ConfigurationError):

    def __init__(self, exception: Exception):
        self.exception = exception

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.exception})"

    def get_segment_val(self, val):
        # We might want this to be a helper function somewhere else 
        # this takes a segment value from a gdt/ldt table and tells you
        # (base, limit, flags, access)
        # we can also set which table we want to use
        #val = int.from_bytes(val, "little")
        #limit_a = val & 0xffff
		#limit_b = ((val >> 48) & 0xf) << 16
		#base_a = (val >> 16) & 0xffffff
		#base_b = ((val >> 56) & 0xff) << 24
		#flags = (val >> 52) & 0xff
		#access = (val >> 40) & 0xff
		#return [base_a | base_b, limit_a | limit_b, flags, access]
        pass
    
    def get_details(self, register, value) -> None:

        # We need the registers or the arguments 
        # to this stuff
        if exception.args[0].errno == uc.UC_ERR_EXCEPTION: 
            # These are CPU exceptions for segment registers
            # For the SS segment register 
            # 1. If the selector is 0 -> error
            # 2. If the selector is not 0 and 
            # a. index is out of range of gdt/ldt table
            # b. 
            # For the SS segment register 
            # c. rpl != cpl and cpl != dpl
            # d. Must be writeable
            # For other segment registers
            # a. Must be readable 
            # b. 
            #if register == uc_x86.UC_X86_REG_SS:
            #if value == 0: 

            pass


