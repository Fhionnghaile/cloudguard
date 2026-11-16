def account_id(session):
    return session.client("sts").get_caller_identity()["Account"]
