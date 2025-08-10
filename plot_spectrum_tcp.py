import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize
from matplotlib.animation import FuncAnimation
import socket
import struct

# Disclaimer: this is mostly AI slop

# Constants
BUFFER_SIZE = 500    # Number of rows in waterfall
FFT_SIZE = 1024    # FFT size for better resolution
#UPDATE_INTERVAL = 10  # Update interval in ms
UPDATE_INTERVAL = 5  # Update interval in ms
Fs = 2e6            # Sampling frequency in Hz
TCP_PORT = 9090      # Port matching the C server program
DC_OFFSET = 20      # Number of bins to skip from DC component

class WaterfallPlotter:
    def __init__(self, sock):
        print("Initializing WaterfallPlotter")
        self.sock = sock
        self.sample_buffer = []
        
        # Set socket to blocking mode
        self.sock.setblocking(True)

        # Initialize plot
        self.fig, self.ax = plt.subplots(figsize=(10, 6))
        self.ax.set_title('Real-time Waterfall Plot from IQ Data')
        self.ax.set_xlabel('Frequency (MHz)')
        self.ax.set_ylabel('Time')

        # Create initial empty waterfall data
        self.waterfall_data = np.zeros((BUFFER_SIZE, FFT_SIZE // 2 - DC_OFFSET))

        # Initialize waterfall plot with adjusted frequency range
        freq_start = (Fs * DC_OFFSET) / (FFT_SIZE * 1e6)
        freq_end = Fs / (2e6)

        # Initialize waterfall plot
        self.im = self.ax.imshow(
            self.waterfall_data,
            aspect='auto',
            cmap='viridis',
            norm=Normalize(vmin=-50, vmax=0),
            extent=[freq_start, freq_end, 0, BUFFER_SIZE],
            origin='lower'
        )
        plt.colorbar(self.im, label='Power (dB)')

    def compute_spectrum(self, iq_samples):
        # Take only the last FFT_SIZE samples if we have more
        if len(iq_samples) > FFT_SIZE:
            iq_samples = iq_samples[-FFT_SIZE:]
        # Pad with zeros if we have fewer samples
        elif len(iq_samples) < FFT_SIZE:
            iq_samples = np.pad(iq_samples, (0, FFT_SIZE - len(iq_samples)))
        
        # Convert list to numpy array if it isn't already
        iq_samples = np.array(iq_samples)
        
        # Apply window function
        window = np.blackman(len(iq_samples))
        windowed_samples = iq_samples * window
        
        # Compute FFT
        spectrum = np.fft.fft(windowed_samples)
        power = np.abs(spectrum[DC_OFFSET:FFT_SIZE//2])**2
        
        # Convert to dB
        power_db = 10 * np.log10(power + 1e-10)
        
        # Normalize
        power_db = power_db - np.max(power_db)
        
        return power_db

    def update_plot(self, frame):
        try:
            # Read the 4-byte header containing number of samples
            header_data = self.sock.recv(4, socket.MSG_WAITALL)
            if len(header_data) == 4:
                num_samples = struct.unpack('I', header_data)[0]
                print(f"Receiving {num_samples} samples")

                # Read all IQ samples (4 bytes per sample: 2 bytes I + 2 bytes Q)
                iq_data_size = num_samples * 4
                iq_data = self.sock.recv(iq_data_size, socket.MSG_WAITALL)
                
                if len(iq_data) == iq_data_size:
                    # Process the received data in pairs of 16-bit signed integers
                    for i in range(0, len(iq_data), 4):
                        # Unpack two 16-bit signed integers (network byte order)
                        i_sample, q_sample = struct.unpack('!hh', iq_data[i:i+4])
                        
                        # Normalize to [-1, 1] range
                        i_sample = float(i_sample) / 256.0
                        q_sample = float(q_sample) / 256.0
                        
                        #print(f"I: {i_sample:.3f}, Q: {q_sample:.3f}")
                        self.sample_buffer.append(complex(i_sample, q_sample))

                    # Process chunks of FFT_SIZE samples
                    while len(self.sample_buffer) >= FFT_SIZE:
                        chunk = self.sample_buffer[:FFT_SIZE]
                        power_db = self.compute_spectrum(chunk)
                        
                        # Update waterfall
                        self.waterfall_data = np.roll(self.waterfall_data, -1, axis=0)
                        self.waterfall_data[-1, :] = power_db
                        
                        # Keep the remainder with 50% overlap
                        self.sample_buffer = self.sample_buffer[FFT_SIZE//2:]

        except socket.error as e:
            print(f"Socket error: {e}")
        except Exception as e:
            print(f"Error in update_plot: {e}")

        # Update the image
        self.im.set_array(self.waterfall_data)
        return [self.im]

    def run(self):
        print("Starting animation")
        self.anim = FuncAnimation(
            self.fig,
            self.update_plot,
            interval=UPDATE_INTERVAL,
            blit=True,
            cache_frame_data=False
        )
        plt.show(block=True)

def main():
    print("Starting program")
    try:
        # Set up TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', TCP_PORT))
        print("Connected to server")

        plotter = WaterfallPlotter(sock)
        plotter.run()

    except Exception as e:
        print(f"Error in main: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()

