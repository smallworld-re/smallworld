    .text
    .set    noreorder
    .set    nomacro
    .set    nomips16
    .set    nomicromips
test:
    # Tests single-stepping delay slot instructions
    # If the branches are not taken correctly,
    # the return value will be incorrect.

    # Set a flag so I can use a conditional jump 
    addiu   $t1,$zero,1
    
    # Set an address so I can dereference
    addiu   $t2,$zero,0x2000
 
    addiu   $v0,$zero,1
    b       .L1
    sw      $v0,($t2)

    # Dead block
    addiu   $v0,$zero,-1
    sw      $v0,($t2)

.L1:
    addiu   $v0,$v0,1
    beq     $t1,$zero,.L2
    sw      $v0,($t2)
    
    b       .L1
    addiu   $t1,$zero,0

    # Dead block
    addiu   $v0,$zero,-1

.L2:
    addiu   $v0,$v0,1
