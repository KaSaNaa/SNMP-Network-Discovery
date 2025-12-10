from screeninfo import get_monitors

class ScreenUtils:
    @staticmethod
    def get_screen_size():
        monitor = get_monitors()[0]
        width_px = monitor.width
        height_px = monitor.height
        return width_px, height_px