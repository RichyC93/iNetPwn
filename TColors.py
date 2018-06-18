class TColors:
    Colors = {
        "red": "\033[0;31m",
        "green": "\033[0;32m",
        "yellow": "\033[0;33m",
        "blue": "\033[0;34m",
        "magenta": "\033[0;35m",
        "cyan": "\033[0;36m",
        "white": "\033[0;37m",
        "end": "\033[0m"
    }
    def ColorStr(self, txt, color):
        if color in self.Colors:
            new_txt = self.Colors[color] + txt + self.Colors["end"]
            print len(new_txt)
            return new_txt
        else: return txt
