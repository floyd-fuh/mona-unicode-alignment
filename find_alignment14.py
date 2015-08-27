# written by floyd - floyd.ch
# all rights reserved
# 
# http://www.floyd.ch
# @floyd_ch
# 
# We are talking about a problem in GF(256). In other words the numbers are modulo 256. Or for the 
# IT people: A byte that wraps around (0xFFFFFFFE + 0x00000002 = 0x00000001).
# 
# Let's first discuss a simple example with 8 inputs (a1..a8). We need the more general case, 
# but so far 8 inputs is the maximum that makes sense. Altough it doesn't make any
# difference. If we solve the general case with (let's say) 16 Inputs we can
# simply set the not needed inputs's to zero and they will be ignored in the model.
# The script runs in the general case and can operate in all cases!
# 
# Inputs (values): a1, a2, ..., a8 mod 256
# Inputs (starts): s1, s2 mod 256
# Inputs (targets/goal): g1, g2 mod 256
# Inputs (prefix and postfix instructions): M, where M is a natural number (including zero)
# Outputs: x1, x2, ..., x8, y1, y2, ..., y8, where these are natural numbers (including zero), and
# a8 is the higher byte of the BufferRegister (e.g. AH), and
# a7 is the lower byte of the BufferRegister (e.g. AL)
# 
# Find (there might be no solution):
# s1+a1*x1+a2*x2+a3*x3+a4*x4+a5*x5+a6*x6+a7*x7+a8* 0-((s2+2*(x1+x2+x3+x4+x5+x6+x7+x8+y1+y2+y3+y4+y5+y6+y7+y8)+M)/256) = g1 mod 256
# s2+a1*y1+a2*y2+a3*y3+a4*y4+a5*y5+a6*y6+a7* 0+g1*y8-2*(x1+x2+x3+x4+x5+x6+x7+x8+y1+y2+y3+y4+y5+y6+y7+y8)-M = g2 mod 256
# 
# Minimise (sum of outputs):
# x1+x2+x3+x4+x5+x6+x7+x8+y1+y2+y3+y4+y5+y6+y7+y8
# 
# Example
# {a1, a2, ... a8} = {9, 212, 0, 0, 32, 28, 50, 188}
# {s1, s2} = {233, 212}
# {g1, g2} = {253, 75}
# 
# Btw the +M and -M in the formula is because we have to get rid of the last zero byte, we do that by injecting
# \x6d, which results in 00 6d 00, meaning we need to add M to the address.
# 
# [Extra constraints!]
# 1. As we first set AH (or whatever higher byte is in start_is) to the correct value
# AH has changed until we want to set AL. Therefore the instruction
# add al, ah will NOT return the correct result, because we assume an old value
# for the AH register! That's why we have a originals (a1...a8) and
# modify them to a21, a22, a23, .. a28 (only for y1...y8, for the x values we're fine)
# 2. Additionally, the following instructions are not allowed (because it would be a lot more
# complicated to calculate in advance the state of the register we are modifying):
# add ah, ah
# add al, al
# Solved by overwriting if random generator produced something like that.
# 3. This program only works if you already managed to get the first
# four bytes of the alignment address right (this program operates
# only on the last four bytes!)
#
#Remarks for re-implementation in mona:
#It is important that we get static and reliable addresses into EAX, ECX, EDX, EBX before we do the math
#Therefore we have to do the following:
#1. Check in mona if EBP is a stackpoint, if yes go to 2. otherwise go to 3.
#2. Pop EBP into EAX: \x55\x6d\x58\6d
#55               PUSH EBP
#00 6d 00     --> unicode "NOP"
#58               POP EAX
#00 6d 00     --> unicode "NOP"
#3. Pop ESP into EBX: \x54\x6d\5B
#54               PUSH ESP
#00 6d 00     --> unicode "NOP"
#5B               POP EBX
#4. Find reliable stack pointers on the stack
#   and pop different ones into EDX, ECX (and EAX if 2. was not executed)
#
#In a lot of cases this is not necessary, but to get full reliability for
#the automated approach, we should really do it. One of the register could
#maybe filled with a timestamp or something! For now, do this manually if 
#necessary!
#
# Cool things about this script: We won't need a NOP sled, the
# next instruction will automatically be the address in our BufferRegister
# and where we can put our (unicode) shellcode


#Inputs - later in mona read it from the breakpoint we're at
start_is = ['ah', 'al'] #Means: Our BufferRegister is chosen as aex
start = 0xE9D4 #EBP last two bytes
goal = 0xFD44 #Address of the first byte of the alignment code.
              #In other words: the address where the first byte of the here
              #generated code is
goal_has_leaked_zero_byte_from_seh = True #If the last zero byte leaks in as the
                                          #start of the instruction,
                                          #we have to prepend an extra \x6d

ebp=0x02cde9d4
ecx=0x0047201c
edx=0x7C9032BC
esp=0x02CDE8F8
#End inputs


testing = False
if testing:
    start = 0xFCF0
    ebp=0x02cdFCF0
    goal=0xFFe2

#Options:
MAGIC_PROBABILITY_OF_ADDING_AN_ELEMENT_FROM_INPUTS=0.25
#Idea of 0.25: We will add every fourth register to the sum.
#This means in average we will increase by 2 instructions every run of 
#randomise.
MAGIC_PROBABILITY_OF_RESETTING=0.04 #an average of about 40 instructions
MAGIC_MAX_PROBABILITY_OF_RESETTING=0.11 #an average of about 20 instructions
#Idea: This is a trade-off - we don't want
#to find no results by resetting to often (and never even
#trying an instruction length of e.g. 500 bytes). On the other
#hand we don't want to search in solutions with a lot of bytes
#when we already found a shorter solution. Therefore we will
#slightly increase it with time.
#End options - don't modify anything below here!

eax = ebp #pre code assignments
ebx = esp

import pprint, time, random, copy
def main():
    originals = []
    ax = theX(eax)
    ah = higher(ax)
    al = lower(ax)
    
    bx = theX(ebx)
    bh = higher(bx)
    bl = lower(bx)
    
    cx = theX(ecx)
    ch = higher(cx)
    cl = lower(cx)
    
    dx = theX(edx)
    dh = higher(dx)
    dl = lower(dx)
    
    start_address = theX(start)
    s1 = higher(start_address)
    s2 = lower(start_address)
    
    goal_address = theX(goal)
    g1 = higher(goal_address)
    g2 = lower(goal_address)
    
    names = ['ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']
    originals = [ah, al, bh, bl, ch, cl, dh, dl]
    sanitiseZeros(originals, names)
    checkDuplicates(originals, names)
    best_result = checkHigherByteBufferRegisterForOverflow(g1, start_is[0], g2)
    
    debug("Best result start: ", best_result)
    #a1, a2, a3, a4, a5, a6, a7, a8 = originals
    #x1, x2, x3, x4, x5, x6, x7, x8 = [0 for i in range(0,8)]
    #y1, y2, y3, y4, y5, y6, y7, y8 = [0 for i in range(0,8)]
    
    #xs = [x1, x2, x3, x4, x5, x6, x7, x8]
    #ys = [y1, y2, y3, y4, y5, y6, y7, y8]
    
    xs = [0 for i in range(0,len(originals))]
    ys = [0 for i in range(0,len(originals))]
    
    
    cyclic = getCyclic(originals)
    mul = 1
    for i in cyclic:
        mul *= i
    
    #We don't even know the value of AH yet (no, it's NOT g1 for high instruction counts)
    cyclic2 = copy.copy(cyclic)
    cyclic2[names.index(start_is[0])] = 9999999
    
    debug("At least %i possibilities..." % mul)
    
    number_of_tries = 0.0
    
    prefix = ""
    postfix = ""
    code_to_get_rid_of_zeros = "add [ebp],ch; " #\x6d --> \x00\x6d\x00
    additionalLength = 0 #Length of the prefix instructions plus postfix instructions in bytes
    if goal_has_leaked_zero_byte_from_seh:
        prefix += code_to_get_rid_of_zeros
        additionalLength += 2
    pass #TODO: get reliable values into EDX, ECX
    if True: #TODO: Check if EBP hasn't been changed
        prefix += "push ebp; "
        prefix += code_to_get_rid_of_zeros
        additionalLength += 4
    else:
        #push something else
        pass #END TODO
    #Don't add code_to_get_rid_of_zeros at the very end, we need the leading zero byte for the ADDs!
    prefix += "pop eax; %spush esp; %spop ebx; " % (code_to_get_rid_of_zeros, code_to_get_rid_of_zeros)
    additionalLength += 10
    
    #Ok, the last ADD command will leak another zero to the next instruction
    #Therefore append a last instruction to get rid of it and add a POSTFIX like
    #00 6d 00     --> the unicode NOP, where the first zero is from the last add command
    postfix += code_to_get_rid_of_zeros
    additionalLength += 2
    
    
    while True:
        #Hmm, we might have a problem to improve the heuristic (random right now)
        #if we don't put the Extra constraints into the formula
        randomise(xs, cyclic)
        randomise(ys, cyclic2)
        
        #[Extra constraint!] 2.
        #not allowed: 
        #add al, al
        #add ah, ah
        xs[names.index(start_is[0])] = 0
        ys[names.index(start_is[1])] = 0
        
        tmp = check2(originals, names.index(start_is[0]), [s1, s2], [g1, g2], xs, ys, additionalLength, best_result)
        if tmp > 0:
            best_result = tmp
            #we got a new result
            printNicely(names, start_is, xs, ys, additionalLength, prefix, postfix)
        #Slightly increases probability of resetting with time
        probability = MAGIC_PROBABILITY_OF_RESETTING+number_of_tries/(10**8)
        if probability < MAGIC_MAX_PROBABILITY_OF_RESETTING:
            number_of_tries += 1.0
        if random.random() <= probability:
            #print "Reset"
            xs = [0 for i in range(0,len(originals))]
            ys = [0 for i in range(0,len(originals))]
    

def sanitiseZeros(originals, names):
    for index, i in enumerate(originals):
        if i == 0:
            warn("""Your %s register seems to be zero, for the heuristic it's much healthier
            if none is zero. Although it might still work, it might also not work or take longer.""" % names[index])
            del originals[index]
            del names[index]
            return sanitiseZeros(originals, names)

def checkDuplicates(originals, names):
    duplicates = len(originals) - len(set(originals))
    if duplicates > 0:
        warn("""Some of the 2 byte registers seem to be the same. There is/are %i duplicate(s):""" % duplicates)
        print ", ".join(names)
        print ", ".join(hexlist(originals))

def checkHigherByteBufferRegisterForOverflow(g1, name, g2):
    overflowDanger = 0x100-g1
    max_instructions = overflowDanger*256-g2
    if overflowDanger <= 3:
        warn("Your BufferRegister's %s register goal value starts pretty high (%s) and might overflow." % (name, hex(g1)))
        warn("Therefore we only look for solutions with less than %i bytes (%s%s to overflow)." % (max_instructions, hex(g1), hex(g2)[2:]))
        warn("This makes our search space smaller, meaning it's harder to find a solution.")
    return max_instructions

def randomise(values, maxValues):
    for index, i in enumerate(values):
        if random.random() <= MAGIC_PROBABILITY_OF_ADDING_AN_ELEMENT_FROM_INPUTS:
            values[index] += 1 
            values[index] = values[index] % maxValues[index]

def check2(as1, index_for_higher_byte, ss, gs, xs, ys, M, best_result):
    g1, g2 = gs
    s1, s2 = ss
    sum_of_instructions = 2*sum(xs) + 2*sum(ys) + M
    if best_result > sum_of_instructions:
        res0 = s1
        res1 = s2
        for index, _ in enumerate(as1):
            res0 += as1[index]*xs[index] % 256
        res0 = res0 - ((g2+sum_of_instructions)/256)
        as2 = copy.copy(as1)
        as2[index_for_higher_byte] = (g1 + ((g2+sum_of_instructions)/256)) % 256
        for index, _ in enumerate(as2):
            res1 += as2[index]*ys[index] % 256
        res1 = res1 - sum_of_instructions
        if g1 == res0 % 256 and g2 == res1 % 256:
            debug("###FOUND")
            debug("a11...a1?", hexlist(as1))
            debug("a21...a2?", hexlist(as2))
            debug("s1, s2", hexlist(ss))
            debug("g1...g2", hexlist(gs))
            debug("x1...x?", xs)
            debug("y1...y?", ys)
            debug("M", M)
            debug("No of bytes of instructions:", sum_of_instructions)
            debug("BufferRegister higher register's (e.g. AH) state after AH operations: %s" % hex(as2[index_for_higher_byte]))
            # if as2[index_for_higher_byte] < s1:
            #     debug("The higher BufferRegister overflowed (e.g. AH) at least once.")
            #     debug("This means you would have to adjust the first 4 bytes of the BufferRegister.")
            #     debug("We don't accept such solutions and 'hope' we find a better.")
            #     return 0
            return sum_of_instructions
    return 0
        
#Old version of check that doesn't support variable as1/as2 lengths, but
#might just be easier to understand if somebody wants to understand this stuff
# def check(as1, as2, ss, gs, xs, ys, best_result):
#     g1, g2 = gs
#     s1, s2 = ss
#     a11, a12, a13, a14, a15, a16, a17, a18 = as1
#     a21, a22, a23, a24, a25, a26, a27, a28 = as2
#     x1, x2, x3, x4, x5, x6, x7, x8 = xs
#     y1, y2, y3, y4, y5, y6, y7, y8 = ys
#     
#     num_of_instr = x1+x2+x3+x4+x5+x6+x7+x8+y1+y2+y3+y4+y5+y6+y7+y8
#     
#     if best_result > num_of_instr:
#         if (s1+a11*x1+a12*x2+a13*x3+a14*x4+a15*x5+a16*x6+a17*x7+a18*x8-((s2+2*(x1+x2+x3+x4+x5+x6+x7+x8+y1+y2+y3+y4+y5+y6+y7+y8)+3)/256)) % 256 == g1 \
#         and (s2+a21*y1+a22*y2+a23*y3+a24*y4+a25*y5+a26*y6+a27*y7+a28*y8-2*(x1+x2+x3+x4+x5+x6+x7+x8+y1+y2+y3+y4+y5+y6+y7+y8))-3 % 256 == g2:
#             debug("###FOUND")
#             debug("a11...a18", hexlist(as1))
#             debug("a21...a28", hexlist(as2))
#             debug("s1, s2", hexlist(ss))
#             debug("g1...g8", hexlist(gs))
#             debug("x1...x8", xs)
#             debug("y1...y8", ys)
#             debug("No of instructions:", num_of_instr)
#             return num_of_instr
#     return 0

def printNicely(names, start_is, xs, ys, additionalLength=0, prefix="", postfix=""):
    #print names, start_is, xs, ys
    resulting_string = prefix
    sum_bytes = 0
    for index, x in enumerate(xs):
        for k in range(0, x):
            resulting_string += "add "+start_is[0]+","+names[index]+"; "
            sum_bytes += 2
    for index, y in enumerate(ys):
        for k in range(y):
            resulting_string += "add "+start_is[1]+","+names[index]+"; "
            sum_bytes += 2
    resulting_string += postfix
    sum_bytes += additionalLength
    result("Use the following instructions (%i resulting bytes (%i bytes injection), paste into metasm shell, remove zero bytes):\n"%(sum_bytes,sum_bytes/2), resulting_string)

def getCyclic(originals):
    cyclic = [0 for i in range(0,len(originals))]
    for index, orig_num in enumerate(originals):
        cycle = 1
        num = orig_num
        while True:
            cycle += 1
            num += orig_num
            num = num % 256
            #print hex(orig_num), hex(num), hex(cycle), index
            #time.sleep(0.2)
            if num == orig_num:
                cyclic[index] = cycle
                break
    return cyclic

def hexlist(list):
    return [hex(i) for i in list]
    

def theX(num):
    res = (num>>16)<<16 ^ num
    #print hex(res)
    return res
    
def higher(num):
    res = num>>8
    #print hex(res)
    return res
    
def lower(num):
    res = ((num>>8)<<8) ^ num
    #print hex(res)
    return res
    
def info(*text):
    print "[INFO   ] "+str(" ".join(str(i) for i in text))
    
def warn(*text):
    print "[WARNING] "+str(" ".join(str(i) for i in text))
    
def result(*text):
    print "[RESULT ] "+str(" ".join(str(i) for i in text))
    
def debug(*text):
    if True:
        print "[DEBUG  ] "+str(" ".join(str(i) for i in text))

main()