/* SDCC's 8051 calling conventions, from both sides.
 *
 * The mcs51_sdcc scenario replaces each function below with a SmallWorld
 * model, which checks the arguments it reads and returns values main keeps
 * for the scenario to check.  The bodies return wrong answers, so a function
 * the model did not replace fails.
 *
 * Built twice: with SDCC's default convention, which passes arguments after
 * the first in each function's static parameters, and with --stack-auto,
 * which passes them on the stack.  sum is variadic, so its arguments are on
 * the stack either way.
 */

__xdata char xbuf[4] = "xd";
__idata char ibuf[4];
__code const char cbuf[] = "code";

long check_args(char c, int i, long l, char *xp, char *ip, const char *cp, float f)
{
    return c + i + l + *xp + *ip + *cp + (long)f;
}

long long twice(long long x)
{
    return x;
}

char *pick(char which)
{
    return which ? xbuf : ibuf;
}

float half(float x)
{
    return x;
}

int sum(int n, ...)
{
    return n;
}

__xdata long r_check_args;
__xdata long long r_twice;
__xdata char r_pick[3];
__xdata float r_half;
__xdata int r_sum;

void main(void)
{
    ibuf[0] = 'i';
    ibuf[1] = 'd';
    r_check_args = check_args('A', -1234, 0x12345678, xbuf, ibuf, cbuf, 1.5f);
    r_twice = twice(0x0102030405060708);
    r_pick[0] = *pick(0);
    r_pick[1] = *pick(1);
    r_pick[2] = *pick(2);
    r_half = half(3.0f);
    r_sum = sum(3, 100, -20, 3);
}
