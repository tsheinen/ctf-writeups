import angr
import sys
from claripy import *
from pwn import *

def main(argv):

    path_to_binary = "sora"
    project = angr.Project(path_to_binary, load_options={'main_opts': {'base_addr': 0x0}})

    x = BVS('x', 0x1e * 8)


    initial_state = project.factory.entry_state(stdin=x)

    # constrain to printable characters
    def char(state, byte):
        return initial_state.solver.And(byte <= '~', byte >= ' ')

    for c in x.chop(8):
        initial_state.solver.add(char(initial_state, c))

    simulation = project.factory.simgr(initial_state)


    simulation.explore(find=0x000012aa)
    if simulation.found:
        solution_state = simulation.found[0]
        r = remote('challenges.auctf.com',30004)
        r.sendline(solution_state.solver.eval(x, cast_to=bytes))
        print(r.recvall())
    else:
        print(simulation.stashes)
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main(sys.argv)