from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class WatchHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def on_modified(self, event):
        if not event.is_directory:
            self.callback("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.callback("created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.callback("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.callback("moved", f"{event.src_path} -> {event.dest_path}")

def start_monitor(path, callback):
    handler = WatchHandler(callback)
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    return observer

def stop_monitor(observer):
    observer.stop()
    observer.join()
