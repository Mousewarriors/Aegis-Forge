import pytest
import docker
from docker_manager import DockerOrchestrator

@pytest.fixture
def orchestrator():
    return DockerOrchestrator()

def test_container_constraints(orchestrator):
    # Create a container
    container = orchestrator.create_vulnerable_agent_container(name="test-security-agent")
    assert container is not None
    
    try:
        # Check security configurations
        container_info = container.client.api.inspect_container(container.id)
        host_config = container_info['HostConfig']
        
        # Network mode should be none
        assert host_config['NetworkMode'] == 'none'
        
        # Capabilities should be dropped
        assert host_config['CapDrop'] == ['ALL']
        
        # No new privileges should be true
        assert 'no-new-privileges:true' in host_config['SecurityOpt']
        
        # Resources
        assert host_config['Memory'] == 134217728 # 128m
        
    finally:
        # Ensure cleanup even if test fails
        orchestrator.cleanup_container(container.id)

def test_auto_cleanup(orchestrator):
    container = orchestrator.create_vulnerable_agent_container(name="test-cleanup-agent")
    container_id = container.id
    
    # Cleanup
    success = orchestrator.cleanup_container(container_id)
    assert success == True
    
    # Verify it's gone
    client = docker.from_env()
    with pytest.raises(docker.errors.NotFound):
        client.containers.get(container_id)
