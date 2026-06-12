"""命令行入口：python -m ipguard_login <subcommand> ..."""
import argparse
import sys

from .crypto import hash_pwd
from .cmds import print_cmd_table
from .login import ocp_login_replay
from .queries import (
    post_login_cmd_replay,
    query_admin_info_via_midtier,
)


def cli(argv=None):
    p = argparse.ArgumentParser(
        prog="ipguard-login",
        description="IPguard3 / OConsole3 OCP 协议登录 + 业务 cmd 客户端",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # ----- login -----
    pl = sub.add_parser("login", help="只做 5 步登录（重放）")
    pl.add_argument("host")
    pl.add_argument("port", type=int)
    pl.add_argument("user")
    pl.add_argument("password")
    pl.add_argument("--computer", default="DESEC")
    pl.add_argument("--winuser", default="happy")
    pl.add_argument("--timeout", type=float, default=30.0)
    pl.add_argument("--no-show-crypto", action="store_true",
                    help="关闭每包加解密展开")

    # ----- hash -----
    ph = sub.add_parser("hash", help="只算密码哈希，不联网")
    ph.add_argument("user")
    ph.add_argument("password")

    # ----- cmds -----
    sub.add_parser("cmds", help="打印 OCP cmd 速查表")

    # ----- query (generic conn#0) -----
    pq = sub.add_parser("query", help="登录后向 conn#0 发任意一个 cmd")
    pq.add_argument("host")
    pq.add_argument("port", type=int)
    pq.add_argument("user")
    pq.add_argument("password")
    pq.add_argument("a2", type=lambda s: int(s, 0))
    pq.add_argument("--sub", type=lambda s: int(s, 0), default=0)
    pq.add_argument("--body-hex", default="")
    pq.add_argument("--sess-zero", action="store_true")
    pq.add_argument("--timeout", type=float, default=15.0)

    # ----- admin (midtier) -----
    pa = sub.add_parser("admin",
                        help="登录 + midtier 握手 + 0x1111 拿管理员资料")
    pa.add_argument("host")
    pa.add_argument("port", type=int)
    pa.add_argument("user")
    pa.add_argument("password")
    pa.add_argument("--timeout", type=float, default=30.0)

    args = p.parse_args(argv)

    if args.cmd == "login":
        return ocp_login_replay(
            args.host, args.port, args.user, args.password,
            computer_name=args.computer, windows_user=args.winuser,
            timeout=args.timeout,
            show_crypto=not args.no_show_crypto,
        )
    if args.cmd == "hash":
        h = hash_pwd(args.user, args.password)
        print(f"username = {args.user}")
        print(f"password = {args.password}")
        print(f"Pwd2     = {h}")
        return h
    if args.cmd == "cmds":
        return print_cmd_table()
    if args.cmd == "query":
        body = bytes.fromhex(args.body_hex) if args.body_hex else b""
        sess = b"\x00" * 8 if args.sess_zero else None
        return post_login_cmd_replay(
            args.host, args.port, args.user, args.password,
            a2=args.a2, a3=args.sub, body=body,
            sess_state_16_24=sess, timeout=args.timeout,
        )
    if args.cmd == "admin":
        return query_admin_info_via_midtier(
            args.host, args.port, args.user, args.password,
            timeout=args.timeout,
        )


if __name__ == "__main__":
    cli()
