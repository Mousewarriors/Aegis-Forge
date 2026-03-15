import docker
import pytest

from docker_manager import DockerOrchestrator


@pytest.fixture
def orchestrator():
    orchestrator = DockerOrchestrator()
    try:
        orchestrator.client.ping()
    except Exception as exc:
        pytest.skip(f"Docker daemon unavailable for integration tests: {exc}")
    return orchestrator


def test_container_constraints(orchestrator):
    container = orchestrator.create_vulnerable_agent_container(name="test-security-agent")
    assert container is not None

    try:
        container_info = container.client.api.inspect_container(container.id)
        host_config = container_info["HostConfig"]

        assert host_config["NetworkMode"] == "none"
        assert host_config["CapDrop"] == ["ALL"]
        assert "no-new-privileges:true" in host_config["SecurityOpt"]
        assert host_config["Memory"] == 134217728
    finally:
        orchestrator.cleanup_container(container.id)


def test_auto_cleanup(orchestrator):
    container = orchestrator.create_vulnerable_agent_container(name="test-cleanup-agent")
    container_id = container.id

    success = orchestrator.cleanup_container(container_id)
    assert success is True

    client = docker.from_env()
    with pytest.raises(docker.errors.NotFound):
        client.containers.get(container_id)
