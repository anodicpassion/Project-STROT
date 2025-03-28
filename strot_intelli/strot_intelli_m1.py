import tensorflow as tf


class STROTIntelli:
    def __init__(self, ) -> None:
        self.__loss = None
        self.__optimizer = None
        self.__model = None

    def build(self) -> None:
        self.__model = tf.keras.Sequential()
        self.__model.add(tf.keras.layers.Input(5, ))
        self.__model.add(tf.keras.layers.Dense(32))
        self.__model.add(tf.keras.layers.Dense(64))
        self.__model.add(tf.keras.layers.Dropout(3))
        self.__model.add(tf.keras.layers.Dense(16))
        self.__model.add(tf.keras.layers.Dense(1))

    def compile(self) -> None:
        self.__model.compile(loss=self.__loss, optimizer=self.__optimizer)
        pass


if __name__ == "__main__":
    intelli = STROTIntelli()
    intelli.build()
    intelli.compile()
