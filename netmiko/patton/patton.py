import time
import re
from netmiko.cisco_base_connection import CiscoSSHConnection
from netmiko.cisco_base_connection import CiscoFileTransfer
from netmiko import log


class PattonBase(CiscoSSHConnection):
    def session_preparation(self):
        """Prepare the session after the connection has been established."""
        self._test_channel_read(pattern=r"[>#]")
        self.set_base_prompt()
        self.disable_paging(command="terminal height 5")
        self.set_terminal_width(command="terminal width 512")
        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    def check_config_mode(self, check_string="(cfg)#", pattern=""):
        """
        Checks if the device is in configuration mode or not.
        Patton does this:
        box(cfg)#
        """
        log.debug(f"pattern: {pattern}")
        self.write_channel(self.RETURN)
        output = self.read_until_pattern(pattern=pattern)
        log.debug(f"check_config_mode: {repr(output)}")
        return check_string in output

    def config_mode(self, config_command="configure", pattern=""):
        """Enter into config_mode.

        :param config_command: Configuration command to send to the device
        :type config_command: str

        :param pattern: Pattern to terminate reading of channel
        :type pattern: str
        """
        output = ""
        if not self.check_config_mode():
            self.write_channel(self.normalize_cmd(config_command))
            # Make sure you read until you detect the command echo (avoid getting out of sync)
            output += self.read_until_pattern(
                pattern=re.escape(config_command.strip()))
            if not re.search(pattern, output, flags=re.M):
                output += self.read_until_pattern(pattern=pattern)
            if not self.check_config_mode():
                raise ValueError("Failed to enter configuration mode.")
        return output


class PattonSSH(PattonBase):
    pass


class PattonTelnet(PattonBase):
    def __init__(self, *args, **kwargs):
        default_enter = kwargs.get("default_enter")
        kwargs["default_enter"] = "\r\n" if default_enter is None else default_enter
        super().__init__(*args, **kwargs)


class PattonFileTransfer(CiscoFileTransfer):
    """Patton SCP File Transfer driver."""

    def __init__(
        self,
        ssh_conn,
        source_file,
        dest_file,
        file_system="/mnt/flash",
        direction="put",
        **kwargs,
    ):
        return super().__init__(
            ssh_conn=ssh_conn,
            source_file=source_file,
            dest_file=dest_file,
            file_system=file_system,
            direction=direction,
            **kwargs,
        )

    def remote_space_available(self, search_pattern=""):
        """Return space available on remote device."""
        return self._remote_space_available_unix(search_pattern=search_pattern)

    def check_file_exists(self, remote_cmd=""):
        """Check if the dest_file already exists on the file system (return boolean)."""
        return self._check_file_exists_unix(remote_cmd=remote_cmd)

    def remote_file_size(self, remote_cmd="", remote_file=None):
        """Get the file size of the remote file."""
        return self._remote_file_size_unix(
            remote_cmd=remote_cmd, remote_file=remote_file
        )

    def remote_md5(self, base_cmd="verify /md5", remote_file=None):
        if remote_file is None:
            if self.direction == "put":
                remote_file = self.dest_file
            elif self.direction == "get":
                remote_file = self.source_file
        remote_md5_cmd = f"{base_cmd} file:{self.file_system}/{remote_file}"
        dest_md5 = self.ssh_ctl_chan.send_command(
            remote_md5_cmd, max_loops=750, delay_factor=4
        )
        dest_md5 = self.process_md5(dest_md5)
        return dest_md5

    def enable_scp(self, cmd=None):
        raise NotImplementedError

    def disable_scp(self, cmd=None):
        raise NotImplementedError
