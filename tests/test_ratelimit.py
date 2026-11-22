import pytest

from guardian_registry.ratelimit import RateLimiter


class FakeTime:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_sliding_window():
    t = FakeTime()
    rl = RateLimiter(2, 10, now=t)
    assert rl.hit("a") == (True, 0.0)
    t.t += 4
    assert rl.hit("a")[0]
    ok, retry = rl.hit("a")
    assert not ok and retry == pytest.approx(6)
    t.t += 6
    assert rl.hit("a")[0]          # first hit slid out of the window


def test_keys_are_independent():
    rl = RateLimiter(1, 60, now=FakeTime())
    assert rl.hit("bank-a")[0] and rl.hit("bank-b")[0]
    assert not rl.hit("bank-a")[0]


@pytest.mark.parametrize("spec,limit,per", [("600/60", 600, 60), (" 5 / 1.5 ", 5, 1.5)])
def test_parse(spec, limit, per):
    rl = RateLimiter.parse(spec)
    assert (rl.limit, rl.per) == (limit, per)


@pytest.mark.parametrize("bad", ["", "10", "a/b", "10/"])
def test_parse_rejects(bad):
    with pytest.raises(ValueError):
        RateLimiter.parse(bad)
