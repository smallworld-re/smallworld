
A possible auto-harness loop

```python
# static analysis to specify initial harness config, hc_0.
# A harness config is probably a JSON file with sections specifying
# cpu, code memory map, contents of memory and stack at start of
# execution, transitive closure of harnessed fn + all called fns,
# external library fns required, etc
hc_0 = Static_analysis(code,harnessing_prereqs)

# results, coverage, failures for each hc across draws
result = {}
trace = {}
fitness = {}
emu_failure = {}
tried = {}

harness_configs = set([hc_0])

# number of draws from a harness used to assess its fitness and gauge failures
n = 100

# top M in terms of fitness of un-tried harnesses to try
m = 10 

while True:

    # get results for any new harnesses in the set    
    for hc in harness_configs:
        if hc not in fitness:
            harness = Make_harness(hc)
            emu_failure[hc] = []
            trace[hc] = []
            # n draws from the harness
            for i in range(n):
                # result of emulation is trace which is probably a
                # little more than just seq of instructions
                t = emulate(code,harness)
                trace[hc].append(t)
                # figure out if there was an emu failure and details
                # (trace needs to contain this info)
                f = failure_in_trace(t)
                emu_failure[hc].append(f)
            # measure coverage by examining the n traces
            coverage[hc] = reasure_coverage(trace[hc])
        # need a single number score.  perhaps just # edges?
        # really this is several numbers?  So maybe its mean +/- std dev?
        fitness[hc]=compute_fitness_score(coverage[hc])
        

    # at this point, *every* harness config has been translated into
    # an actual harness which has been run for n draws and we have
    # traces, failures (or not), coverage for each. Also a fitness
    # score for each harness config.
    #
    # Now, we want to create new harness configs likely to work well.
    # Under the assumption that there will be too many to try all
    # maybe we use fitness to select top-M not yet "tried" to use.

    # generate at most m new harnessing configs
    for i in range(m):
        if num_untried(hc, tried) == 0:
            break
        # highest fitness hc that is un-tried
        hc = get_top_fitness_untried(fitness, tried)
        tried[hc] = []
        # modify harness to address any observed emulation failures
        any_failures = False
        hc_new = copy(hc)
        for i in range(n):
            t = trace[hc][i]
            f = emu_failure[hc][i]
            if f:
                any_failures = True
                # adjust hc_new in a way likely to fix failure f
                hc_new = mitigate_failure(hc_new, f, t)                
        if any_failures:
            # this hc had emulation failures
            # add hc_new to set and move on
            harness_configs.add(hc_new)
            continue
        # ok no emulation failures. what about half-covered conditionals?
        for cond,bnt,trace_info in get_half_covered_conditionals(coverage[hc]):
            # cond is conditional that is 1/2 covered by hc given n draws
            # bnt is branch-not-taken i.e. True or False
            # trace_info is list of (seed,ind) traces that at least get to cond
            #   seed is seed used to generate trace
            #   ind is index for trace in trace[hc]
            harness = Make_harness(hc)
            # this would be use symbolic execution + SMT solving to try to flip cond along trace
            # returns required initial state to follow trace to cond and then 
            init_state = symex_flip_cond(code,harness,seed,trace,cond,~bnt)
            if not init_state:
                # can't flip it
                continue
            # SMT flipped it. somehow adapt harness config so that
            # this seemingly missing initial state is more likely to be drawn
            hc_new = adapt_hc_to_missing_init_state(hc,init_state)
            harness_configs.add(hc_new)
        
```            

        
    
     



