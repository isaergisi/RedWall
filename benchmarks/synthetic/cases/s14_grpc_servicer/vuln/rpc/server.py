import subprocess

from rpc import runner_pb2_grpc


class Runner(runner_pb2_grpc.RunnerServicer):
    def Run(self, request, context):  # gt:source
        out = subprocess.check_output("convert " + request.path, shell=True)  # gt:sink gt:source
        return out
