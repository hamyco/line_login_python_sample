# coding: utf-8

class UserMetaDataManager(object):

    def __init__(self):
        self.__meta_data = {}

    def append_user_meta_data(
            self,
            session_id,
            user_name=None,
            user_picture_url=None
    ):
        self.__meta_data[session_id] = UserMetaData(
            user_name,
            user_picture_url
        )

    def update_meta_data(self, session_id, key, value):
        if session_id not in self.__meta_data.keys():
            raise
        self.__meta_data[session_id].__dict__[key] = value

    def remove_user_meta_data(self, session_id):
        if session_id in self.__meta_data.keys():
            self.__meta_data.pop(session_id)

    def get_user_meta_data(self, session_id):
        if session_id in self.__meta_data.keys():
            return self.__meta_data[session_id]

    def get_user_meta_data_by_state(self, state):
        for k in self.__meta_data.keys():
            user_meta_data = self.__meta_data[k]
            if 'state' not in user_meta_data.__dict__.keys():
                continue
            if user_meta_data.state == state:
                return user_meta_data


class UserMetaData(object):
    def __init__(
            self,
            user_name,
            user_picture_url
    ):
        self.user_name = user_name
        self.user_picture_url = user_picture_url
