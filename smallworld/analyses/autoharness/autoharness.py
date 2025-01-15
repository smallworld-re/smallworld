
# A possible auto-harness loop




# static analysis of the code to make an initial stab
# at a "harness config"
hc = Static_analysis(code,harnessing_prereqs)

hc_old = None
res_old = None

while True:
    
    res = evaluate_hc(code,hc)

    # discard "new" hc if it is not better than old
    if hc_old and is_not_better(hc,res,hc_old,res_old):
        hc = hc_old

    # save old hc and results
    hc_old = hc
    res_old = res
    
    # choose one of three ways to try to change hc
    while True:
        d = random.randint(1,3)
        if d==1:
            # fix an emulation failure 
            (tfs,c,l) = res
            (t,f) = pick_an_emu_failure(tfs)
            if f is None: # there are none
                continue
            hc = address_failure(t,f,hc)
        elif d==2:
            # try to improve coverage
            unflipped_branches = find_unflipped_branches(tfs)
            u = random.choice(unflipped_branches)
            # use symbolic exec?
            t2 = flip_branch(u,tfs)
            if not t2:
                # not able to flip it
                continue
            # success! t2 is trace that flips u
            # revise hc to be more likely to additionally have t2
            hc = address_unflipped_branch(u,t2,tfs,hc)
        elif d==3:
            # try to abstract things.
            # there might be many ways but here's one:
            si = divine_struct_info(tfs)
            hc = incorporate_struct_info(sf,hc)
        # only quit this loop when we have a new hc to try
        if not(hc.equals(hc_old)):
            break
            

def evaluate_hc(code,hc):
    # instantiate harness from config
    harness = make_harness(hc)
    tfs = []
    # n draws from the harness
    for i in range(n):
        # result of emulation is trace maybe plus some stuff
        t = emulate(code,harness)
        # figure out if there was an emu failure and details
        f = failure_in_trace(t)
        tfs.append((t,f))
    # compute coverage for harness from traces    
    c = compute_coverage(tfs)
    # compute loveliness of the hc (is it very concrete, or very abstract)?
    l = compute_lovlieness(hc)
    return (tfs,c,l)
    

def is_not_better_than(hc1,res1,hc2,res2):

    #
    # first, coverage
    # if res1 covers everything res2 does and more it is strictly better
    # if res1 has same coverage as res2 move on to other considerations
    # if res1 covers some things res2 does but not all ... then what the hell
    #
    # something with failures?
    #
    # if we can't decide based on coverage then look at the config itself
    # if hc1 has some forms of abstraction like struct defs which it uses 
    #   and hc2 does not, then hc1 is better
    # if they both have a struct def and one has more fields then it is better
    # etc
    
     
