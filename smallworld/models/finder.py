from .. import state, utils


def model_for_name(
    arch: str, mode: str, byteorder: str, abi: str, name: str, address: int
):
    return utils.find_subclass(
        state.models.ImplementedModel,
        lambda x: x.arch == arch
        and x.mode == mode
        and x.byteorder == byteorder
        and x.abi == abi
        and x.name == name,
        address,
    )
