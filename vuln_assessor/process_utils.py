from __future__ import annotations


def windows_hidden_process_kwargs(platform_name: str, create_no_window_flag: int) -> dict[str, int]:
    if platform_name != "nt" or not create_no_window_flag:
        return {}
    return {"creationflags": int(create_no_window_flag)}
