# Angr-based NWBT analysis

This example analysis uses a very simple 
data type model to help a user inform
angr how to handle data Not Written By Trace.

## CONOPS:

**Goal:** User leverages datatype information to bootstrap environment mode

1. The user builds an initial set of typedefs.
2. The user assigns typedefs to uninitialized parts of the initial state.
3. The executor attempts to access typed but uninitialized data
4. The executor provides the user options for initializing the data based on its type.
5. The user selects an option.
6. The execution can continue, thanks to refined environment model. 

Ultimately, I'd want to use typedef info for more than this:

- Extract environment from an execution path
- Detect nonsensical/contradictory uses of typed data

However, this is something I whipped up in less than two weeks.
It's very much a work in progress.

## The Type Model

My incredibly simple type model has the following grammar:

- **Primitive:** An opaque bitvector.
	- Has a configurable name
	- Has a configurable size in bytes
- **Pointer:** A reference to another datatype.
	- Has a size in bytes, determined by the architecture.
	- Has a referenced datatype.
- **Struct:** An ordered sequence of other data types
	- Has a name
	- Has an ordered sequence of fields.
		- Each field has a unique name
		- Each field has a datatype
	- Has a size in bytes, determined by its fields.

## Running the Example Script

There are two example scripts that leverage the NWBT executor.

`examples/angr_nwbt.py` includes example initial configuration. 
It currently works for the `struct.bin` and `tree.bin`test cases.

`examples/angr_generic.py` just runs the NWBT executor.
This works on any program, but the user will need
to define their own type definitions at runtime.

**FIXME:** I haven't implemented on-the-fly datatype definition yet.

```
smallworld/examples/angr_nwbt.py [OPTIONS] infile

Addresses can be specified as decimal integers,
or hex integers with the prefix '0x'

Arguments:

infile:		Input binary to analyze

Options:
-a arch:	Specify the architecture of infile.
			Defaults to "x86_64".
-b addr: 	Specify a base address for infile.
			Defaults to 0x100000.
-e addr:	Specify an entrypoint address of infile.
			This is interpreted relative to the base address.
			This is ignored for ELF inputs.
			Defaults to 0x0
-F format:	Specify the binary format:
			- `blob`: Treat infile as raw machine code.
			- `elf`: Treat infile as an ELF file.
-v:			Enable verbose logging.
```

## Interacting with the example

Execution starts at a single entrypoint,
and explores forward through all satisfiable program paths.

The executor explores the program in steps,
advancing each available program path by one basic block.

During exploration, the executor may ask the user for 
help resolving one of the following cases:

- Uninitialized read from a register
- Uninitialized read from a memory region
- Dereference of a symbolic pointer
- Dereference of a conditional symbolic expression

At the end of each step, the analysis prints a summary
of the current set of program paths.

**NB:** All input prompts work as follows:

- Options are case-insensitive.
- You can input the full prompt name, or the first letter.
- An option displayed in all caps is the default; just hit `enter` to trigger it.
- Tab-completion and arrow-key navigation are not supported.
- To force-quit durring a prompt, press `Ctrl-C` followed by `enter`.

### End-of-Step Summary

Once a step is complete, the analysis will print
details of the current machine state for each
program path available after the last step.

Each program path can be in one of the following states:

- `active`: The path is live and ready to continue.
- `exited`:	The path has exited the code snippet.
- `halted`: The user killed this execution path.
- `unsat`: 	The path's constraints represent a contradiction.
- `error`:	The executor encounted an error evaluating this path.

**N.B.:** Inactive paths are only displayed once,
following the step during which they became inactive.

Each machine state will include the following details:

- The disassembly of the code block that will be executed next
- Values of registers referenced during this path
- Values of memory referenced during this path
- Constraints governing this path
- Type bindings for registers
- Type bindings for symbolic variables
- Allocation addresses for each data type

Once the summary is complete, the program will ask the user
if they want to continue.

### Resolving a typed uninitialized value

This happens if an uninitialized register, memory region,
or symbolic address has an associated data type.

All datatypes offer the following options:

- `placeholder`: Initialize with a placeholder symbolic expression.
	- This creates a symbolic expression representing the type:
		- primitives and pointers will have a single symbol.
		- Structs will be a concatenation of several.
	- Placeholder symbols are considered partially-initialized
		- They are considered initialized if read.
		- They are considered uninitialied if dereferenced.
	- Symbols within the placeholder are bound to their associated data types.
- `const`: Initialize with a user-provided constant.
	- You will be prompted to input a hex literal.
- `null`: Initialize with zero.
- `ignore`:	Use whatever angr recommends, usually something messy.
	- Use the `details` option to print the recommendation.
	- **N.B.:** Recommendations are not available for symbolic dereferences.
- `details`: Print details of the current problem
	- Includes details of the current machine state
	- Includes details of the value being initialized
	- Re-prompts afterwards.
- `stop`: Kill the current execution path.
- `quit`: Exit the example script
- `help`: Print usage information very similar to this list.
	- Re-prompts afterwards.

Pointer datatypes offer two additional options:

- `alloc`: Initialize with the address of a new instance of this type.
	- Instance is created on the heap
	- Instance is populated as if by the `placeholder` operation.
- `reuse`: Initialize with the address of a previously-allocated instance of this type.
	- Displays existing instances
	- You will be prompted to select one
	- If no instances of this type exist, this will say so and re-prompt.
					
If the value you select renders this path unsatisfiable,
the analysis will reject your choice and re-prompt.

### Resolving an untyped uninitialized value

If an uninitialized register, memory region,
or symbolic address has no type, you will be prompted to provide one.

The available options are as follows:

- `ignore`: Do not associate any data type.
	- Value is initialized with whatever angr recommends.
- `bind`: Manualy specify a datatype to bind.
	- **N.B.:** This isn't implemented yet.
	- This will drop you into the "typed uninitialized" prompt to specify a value.
- `details`: Print details of the current problem
	- Includes details of the current machine state
	- Includes details of the value with a missing type
	- Re-prompts afterwards.
- `stop`: Kill the current execution path.
- `quit`: Exit the example script
- `help`: Print usage information very similar to this list.
	- Re-prompts afterwards.
	
### Resolving a conditional symbolic address

This triggers if the executor tries to dereference
a symbolic expression that contains a ternary operator.

This happens if you use conditional data flow, such as a `cmov` instruction,
with an under-constrained test expression.
angr's  method of resolving this kind of case sucks, so I extended it.

The available options are as follows:

- `fork`: Split this path into separate paths for each possible evaluation.
	- Each new state is constrained so that `addr == evaluation`
	- This turns conditional data flow into conditional control flow.
- `chose`: Select one possible evaluation to use
	- The successor state is constrained so that `addr == evaluation`
	- This constrains the under-constrained data flow.
- `ignore`: Use angr's default resolution.
	- The successor state is constrained so that `addr == concrete-addr`.
	- This is the same as saying 'some evaluation of addr equals concrete-addr'
	- In practice, this fails for a few reasons:
		- It under-constrains; that binding could always apply to "the other" evaluation.
		- Concretization doesn't memoize; it will happily concretize the same expression to multiple values.
- `details`: Print details of the current problem
	- Includes details of the current machine state
	- Includes details of the conditional address
	- Includes the available evaluations.
	- Re-prompts afterwards.
- `stop`: Kill the current execution path.
- `quit`: Exit the example script
- `help`: Print usage information very similar to this list.
	- Re-prompts afterwards.
