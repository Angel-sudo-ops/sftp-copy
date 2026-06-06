import tkinter as tk
from tkinter import ttk, font

class ToolTip:
    def __init__(self, widget, text, delay=400, fade_duration=500):
        self.widget = widget
        self.text = text
        self.delay = delay  # delay before showing tooltip in milliseconds
        self.fade_duration = fade_duration  # duration of fade effect in milliseconds
        self.tooltip_window = None
        self.id = None
        self.opacity = 0
        self.is_fading_out = False

        self.widget.bind("<Enter>", self.schedule_tooltip)
        self.widget.bind("<Leave>", self.start_fade_out)
        self.widget.bind("<Button-1>", self.on_click)
        self.widget.winfo_toplevel().bind("<Motion>", self.check_motion)

    def schedule_tooltip(self, event):
        self.cancel_tooltip()
        if not self.is_fading_out:
            self.id = self.widget.after(self.delay, self.show_tooltip)

    def show_tooltip(self):
        if self.tooltip_window or not self.text:
            return
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tw.attributes('-alpha', 0.0)  # Start with full transparency

        style = ttk.Style()
        style.configure("Tooltip.TLabel", background="white", relief='solid', borderwidth=1, font=("helvetica", "8", "normal"))

        label = ttk.Label(tw, text=self.text, 
                          style="Tooltip.TLabel"
                        #   justify='left',
                        #   background="white", relief='solid', borderwidth=1,
                        #   font=("helvetica", "8", "normal")
                          )
        label.pack(ipadx=1)

        self.is_fading_out = False
        self.fade_in()

    def fade_in(self):
        if self.opacity < 1.0 and not self.is_fading_out:
            self.opacity += 0.05
            self.tooltip_window.attributes('-alpha', self.opacity)
            self.tooltip_window.after(int(self.fade_duration / 20), self.fade_in)
        else:
            if self.opacity >= 1.0:
                self.opacity = 1.0

    def start_fade_out(self, event=None):
        if self.tooltip_window and not self.is_fading_out:
            self.is_fading_out = True
            self.fade_out()

    def fade_out(self):
        if self.opacity > 0:
            self.opacity -= 0.05
            if self.tooltip_window:
                self.tooltip_window.attributes('-alpha', self.opacity)
                self.tooltip_window.after(int(self.fade_duration / 20), self.fade_out)
        else:
            if self.tooltip_window:
                self.tooltip_window.destroy()
                self.tooltip_window = None
                self.opacity = 0  # Reset opacity for the next tooltip
            self.is_fading_out = False

    def cancel_tooltip(self):
        if self.id:
            self.widget.after_cancel(self.id)
            self.id = None

    def check_motion(self, event):
        widget_under_cursor = self.widget.winfo_containing(event.x_root, event.y_root)
        if widget_under_cursor != self.widget and self.tooltip_window and not self.is_fading_out:
            self.start_fade_out()
    
    def on_click(self, event):
        # Reset the tooltip logic on click to ensure it can still appear
        self.cancel_tooltip()
        if self.tooltip_window:
            self.start_fade_out()
        self.schedule_tooltip(event)


# Tooltip Logic
def create_tooltip_btn(widget, text_var, root, text_resolver=None):
    tooltip = tk.Label(root, text="", bg="white", relief="solid", bd=1, font=("helvetica", "8", "normal"), padx=1, pady=1)
    tooltip.place_forget()

    def on_enter(event):
        if text_resolver:
            text_var.set((text_resolver()))
        tooltip.config(text=text_var.get())
        # Place it in the global reference
        # tooltip.place(x=400, y=160)

        widget = event.widget

        # Use widget-relative placement inside the same parent
        tooltip.place(
            in_=widget,  # Anchor to the button
            relx=0.5,    # Centered horizontally
            rely=0.0,    # Just above the button
            x=-7,
            y=0,       # Shift up
            anchor="s"   # Anchor the bottom center of tooltip to relx/rel...
        )

    def on_leave(event):
        tooltip.place_forget()

    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave)


def show_status_message(
    root,
    status_label,
    message,
    duration=3000,
    fade_steps=10,
    start_color="#00aa00",
    end_color="#aaaaaa"
    ):
    """Show a temporary status message that fades from start_color to end_color before disappearing."""
    status_label.config(text=message, foreground=start_color)

    step_duration = duration // fade_steps

    # Helper to convert hex to RGB tuple
    def hex_to_rgb(hex_color):
        hex_color = hex_color.lstrip("#")
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    # Helper to convert RGB tuple to hex
    def rgb_to_hex(rgb_tuple):
        return "#{:02x}{:02x}{:02x}".format(*rgb_tuple)

    start_rgb = hex_to_rgb(start_color)
    end_rgb = hex_to_rgb(end_color)

    def fade(step=0):
        if step >= fade_steps:
            status_label.config(text="")
            return

        # Interpolate between start and end RGB values
        current_rgb = tuple(
            int(start + (end - start) * (step / fade_steps))
            for start, end in zip(start_rgb, end_rgb)
        )

        faded_color = rgb_to_hex(current_rgb)
        status_label.config(foreground=faded_color)

        root.after(step_duration, lambda: fade(step + 1))

    root.after(duration, fade)


############################### Entry tooltip ###################################3

class EntryTooltip:
    def __init__(self, widget, separator=","):
        self.widget = widget
        self.tipwindow = None
        self.text = ""
        self.separator = separator

    def format_text(self, raw_text):
        # Break at separators
        chunks = [chunk.strip() for chunk in raw_text.split(self.separator)]
        return "\n".join(chunks)

    def showtip(self, raw_text):
        if self.tipwindow or not raw_text:
            return
        
        formatted_text = self.format_text(raw_text)

        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5

        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=formatted_text,
            justify=tk.LEFT,
            background="white",
            relief=tk.SOLID,
            borderwidth=1,
            font=("Segoe UI", 9),
            padx=4,
            pady=2
        )
        label.pack()

    def hidetip(self):
        if self.tipwindow:
            self.tipwindow.destroy()
            self.tipwindow = None


def attach_tooltip_on_overflow(entry_widget, text_var, separator=","):
    tooltip = EntryTooltip(entry_widget, separator=separator)

    def check_overflow():
        f = font.Font(font=str(entry_widget.cget("font")))
        text_width = f.measure(text_var.get())
        widget_width = entry_widget.winfo_width() - 4  # small padding for borders
        tooltip.text = text_var.get() if text_width > widget_width else ""

    def on_enter(event):
        check_overflow()
        if tooltip.text:
            tooltip.showtip(tooltip.text)

    def on_leave(event):
        tooltip.hidetip()

    def on_update(*args):
        if tooltip.tipwindow:
            check_overflow()
            if tooltip.text:
                tooltip.showtip(tooltip.text)
            else:
                tooltip.hidetip()

    def on_resize(event):
        on_update()

    entry_widget.bind("<Enter>", on_enter)
    entry_widget.bind("<Leave>", on_leave)
    entry_widget.bind("<Configure>", on_resize)
    text_var.trace_add("write", on_update)

    entry_widget.after(100, check_overflow)



################################################### Table Tooltip ###################################################
# Revisit this class later, add target column
class TreeviewTooltip:
    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None
        self.widget.bind("<Motion>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        # Identify the row and column under the mouse
        item_id = self.widget.identify_row(event.y)
        column = self.widget.identify_column(event.x)

        # If not hovering over a valid cell, hide the tooltip
        if not item_id or column != "#4":  # "#4" corresponds to the 4th column (Description)
            self.hide_tooltip()
            return

        # Get the description text from the identified row
        item_values = self.widget.item(item_id, "values")
        description = item_values[3] if len(item_values) > 3 else ""  # Safeguard against missing data

        if not description.strip():  # Hide the tooltip if there's no content
            self.hide_tooltip()
            return

        # Get the width of the column
        column_width = self.widget.column(column, "width")

        # Create a temporary label to measure text width
        temp_label = tk.Label(
            self.widget,
            text=description,
            font=("Segoe UI", 10),
        )
        temp_label.update_idletasks()  # Ensure accurate width calculation
        text_width = temp_label.winfo_reqwidth()
        temp_label.destroy()

        # Show the tooltip only if the text width exceeds the column width
        if text_width <= column_width:
            self.hide_tooltip()
            return

        # Calculate the position for the tooltip
        try:
            x, y, _, height = self.widget.bbox(item_id, column)
        except (ValueError, TypeError):
            self.hide_tooltip()
            return

        x += self.widget.winfo_rootx()
        y += self.widget.winfo_rooty() + height

        # Create the tooltip window if it doesn't exist
        if self.tipwindow:
            return

        self.tipwindow = tk.Toplevel(self.widget)
        self.tipwindow.wm_overrideredirect(True)  # Remove window decorations
        self.tipwindow.wm_geometry(f"+{x}+{y}")

        # Add the tooltip content
        label = tk.Label(
            self.tipwindow,
            text=description,
            background="lightyellow",
            relief="solid",
            borderwidth=1,
            font=("Segoe UI", 10),
            wraplength=400,  # Set a maximum width for the tooltip
        )
        label.pack(ipadx=5, ipady=2)

    def hide_tooltip(self, event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
            self.tipwindow = None

