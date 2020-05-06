Feature: PowerStore CSI interface
    As a consumer of the CSI interface
    I want to test service methods
    So that they are known to work

@current
    Scenario: Identity GetPluginInfo good call
      Given a PowerStore service on "controller"
      When I call GetPluginInfo
      Then a valid GetPluginInfoResponse is returned

@current
    Scenario: Identity GetPluginCapabilities good call
      Given a PowerStore service on "controller"
      When I call GetPluginCapabilities
      Then a valid GetPluginCapabilitiesResponse is returned

@current
    Scenario: Node NodeGetCapabilities good call
      Given a PowerStore service on "controller"
      When I call NodeGetCapabilities
      Then a valid NodeGetCapabilitiesResponse is returned

@current
    Scenario: Call ControllerGetCapabilities
      Given a PowerStore service on "controller"
      When I call ControllerGetCapabilities
      Then a valid ControllerGetCapabilitiesResponse is returned

@current
    Scenario Outline: Calls to validate volume capabilities
      Given a PowerStore service on "controller"
      When I call Probe
      And I call ValidateVolumeCapabilities with voltype <voltype> access <access>
      Then the error contains <errormsg>

      Examples:
      | voltype    | access                     | errormsg                                                          |
      | "block"    | "single-writer"            | "none"                                                            |
      | "block"    | "single-reader"            | "none"                                                            |
      | "block"    | "multi-reader"             | "none"                                                            |
      | "mount"    | "multi-writer"             | "multi-node with writer(s) only supported for block access type"  |
      | "mount"    | "multi-node-single-writer" | "multi-node with writer(s) only supported for block access type"  |
      | "mount"    | "unknown"                  | "access mode cannot be UNKNOWN"                                   |
      | "none "    | "unknown"                  | "unknown access type is not Block or Mount"                       |
      | "mount"    | "single-writer"            | "none"                                                            |
      | "mount"    | "single-writer"            | "none"                                                            |
      | "mount"    | "single-writer"            | "none"                                                            |

@current
    Scenario: Calls to validate volume capabilities with not exist volume
      Given: a PowerStore service on "controller"
      When I call Probe
      And I call ValidateVolumeCapabilities with not exist volume
      Then the error contains "not found"

@current
    Scenario: Calls to validate volume capabilities with failure
      Given: a PowerStore service on "controller"
      When I call Probe
      And I call ValidateVolumeCapabilities with failure
      Then the error contains "failure checking volume status for capabilities"

@current
    Scenario: Identity Probe good call
      Given a PowerStore service on "controller"
      When I call Probe
      Then a valid ProbeResponse is returned

@current
    Scenario Outline: Identity Probe with error
      Given a PowerStore service on "node"
      And I rewrite PowerStore service option <option> <value>
      When I call Probe
      Then the error contains <errormsg>

      Examples:
      | option             | value                 | errormsg                           |
      | "Endpoint"         | ""                    | "missing PowerStore API endpoint"  |
      | "User"             | ""                    | "missing PowerStore API user"      |
      | "Password"         | ""                    | "missing PowerStore API password"  |

@current
    Scenario: Call NodeGetInfo and validate NodeId
      Given a PowerStore service on "controller"
      When I call NodeGetInfo
      Then a valid NodeGetInfoResponse is returned

@current
    Scenario: Call NodeGetInfo without Node Id File
      Given a PowerStore service on "node"
      And I rewrite PowerStore service option "NodeIDFilePath" "non_existent_file"
      When I call NodeGetInfo
      Then the error contains "Could not readNode ID file"

@current
    Scenario: Create volume good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateVolume "volume1" "16"
      Then a valid CreateVolumeResponse is returned

@current
    Scenario Outline: Create volume with validation error
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateVolume <name> <size> with error
      Then the error contains <errormsg>

      Examples:
      | name         | size        | errormsg                                  |
      | ""           | "16"        | "Name cannot be empty"                    |
      | "volume"     | "131073"    | "can't be more than maximum size bytes"   |

@current
    Scenario Outline: Create volume with requireProbe error
      Given a PowerStore service on "controller"
      And I rewrite PowerStore service option <option> <value>
      When I call Probe
      And I reset PowerStore client
      And I call CreateVolume "volume1" "8" with error
      Then the error contains <errormsg>

      Examples:
      | option         | value     | errormsg                                  |
      | "AutoProbe"    | "false"   | "Controller Service has not been probed"  |
      | "Password"     | ""        | "failed to probe/init plugin"             |

@current
    Scenario: Idempotent create volume with duplicate name
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateExistVolume "volume2" "16"
      Then a valid CreateVolumeResponse is returned

@current
    Scenario: Idempotent create volume with duplicate name and different sizes
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateExistVolumeIncompatible "volume3" "8"
      Then the error contains "already exists but is incompatible volume size"

@current
    Scenario: Сreate volume with duplicate name and error
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateExistVolumeError "volume4" "8"
      Then the error contains "can't find volume"

@current
    Scenario: Сreate volume failure scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call failure CreateVolume "volume4" "8"
      Then the error contains "Unknown error"

@current
    Scenario: Delete volume good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call DeleteVolume "volume1"
      Then a valid DeleteVolumeResponse is returned

@current
    Scenario: Delete non-existing volume
      Given a PowerStore service on "controller"
      When I call Probe
      And I call DeleteNonExistVolume "volume3"
      Then a valid DeleteVolumeResponse is returned

@current
    Scenario: Call GetCapacity good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call GetCapacity
      Then a valid GetCapacityResponse is returned

@current
    Scenario: Call GetCapacity with Probe error
      Given a PowerStore service on "controller"
      And I rewrite PowerStore service option "Endpoint" ""
      When I call Probe
      And I reset PowerStore client
      And I call GetCapacity with Probe error
      Then the error contains "missing PowerStore API endpoint"

@current
    Scenario: Call GetCapacity failure scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call failure GetCapacity
      Then the error contains ""

@current
    Scenario: Call GetCapacity with Volume Capabilities
      Given a PowerStore service on "controller"
      When I call Probe
      And I call GetCapacity with volume capabilities voltype "none" access "unknown"
      Then the error contains "unknown access type is not Block or Mount"

@current
    Scenario: Call ListVolumes good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call ListVolumes
      Then a valid ListVolumesResponse is returned

@current
    Scenario: Call ListVolumes with Probe error
      Given a PowerStore service on "controller"
      And I rewrite PowerStore service option "Endpoint" ""
      When I call Probe
      And I reset PowerStore client
      And I call ListVolumes with cache and start token ""
      Then the error contains "missing PowerStore API endpoint"

@current
    Scenario Outline: Call ListVolumes with StartToken error
      Given a PowerStore service on "controller"
      When I call Probe
      And I update volume cache
      And I call ListVolumes with cache and start token <token>
      Then the error contains <errormsg>

      Examples:
      | token        | errormsg                        |
      | "not_uint32" | "Unable to parse StartingToken" |
      | "3"          | "> len(volumes)="               |

@current
  Scenario: Call ListVolumes failure scenario
    Given a PowerStore service on "controller"
    When I call Probe
    And I call failure ListVolumes
    Then the error contains "unable to list volumes"

@current
    Scenario: Create snapshot good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateSnapshot "snap1" "39bb1b5f"
      Then a valid CreateSnapshotResponse is returned

@current
    Scenario Outline: Create snapshot with validation error
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateSnapshot <name> <volid> with error
      Then the error contains <errormsg>

      Examples:
      | name         | volid       | errormsg                                |
      | ""           | "39bb1b5f"  | "Name cannot be empty"                  |
      | "snap"       | ""          | "volume ID to be snapped is required"   |

@current
    Scenario Outline: Create snapshot with requireProbe error
      Given a PowerStore service on "controller"
      And I rewrite PowerStore service option <option> <value>
      When I call Probe
      And I reset PowerStore client
      And I call CreateSnapshot "snap1" "39bb1b5f" with error
      Then the error contains <errormsg>

      Examples:
      | option         | value     | errormsg                                  |
      | "AutoProbe"    | "false"   | "Controller Service has not been probed"  |
      | "Password"     | ""        | "failed to probe/init plugin"             |

@current
    Scenario: Idempotent create snapshot with duplicate name
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateExistingSnapshot "snap1" "39bb1b5f"
      Then a valid CreateSnapshotResponse is returned

@current
    Scenario: Idempotent create snapshot with duplicate name and different sourceID
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateExistingSnapshotIncompatible "snap1" "0000" with error
      Then the error contains "rpc error: code = AlreadyExists desc = snapshot with name 'snap1' exists, but SourceVolumeId 0000 doesn't match"

@current
    Scenario: Сreate snapshot with duplicate name and error
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateExistingSnapshotError "snap2" "39bb1b5f"
      Then the error contains "rpc error: code = Internal desc = can't find snapshot 'snap2'"

@current
    Scenario: Сreate snapshot failure scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call failure CreateSnapshot "snap1" "39bb1b5f"
      Then the error contains "Unknown error"

@current
    Scenario: Delete snapshot good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call DeleteSnapshot "39bb1b5f"
      Then a valid DeleteSnapshotResponse is returned

@current
    Scenario: Delete snapshot with validation error
      Given a PowerStore service on "controller"
      When I call Probe
      And I call DeleteSnapshot "" with error
      Then the error contains "snapshot ID to be deleted is required"

@current
    Scenario Outline: Delete snapshot with requireProbe error
      Given a PowerStore service on "controller"
      And I rewrite PowerStore service option <option> <value>
      When I call Probe
      And I reset PowerStore client
      And I call DeleteSnapshot "snap1" with error
      Then the error contains <errormsg>

      Examples:
      | option         | value     | errormsg                                  |
      | "AutoProbe"    | "false"   | "Controller Service has not been probed"  |
      | "Password"     | ""        | "failed to probe/init plugin"             |

@current
    Scenario: Delete non-existing snapshot
      Given a PowerStore service on "controller"
      When I call Probe
      And I call DeleteNonExistingSnapshot "snap2"
      Then a valid DeleteSnapshotResponse is returned

@current
    Scenario: Call ListSnapshots good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call ListSnapshots "snap1" "vol1"
      Then a valid ListSnapshotsResponse is returned

@current
    Scenario Outline: Call ListSnapshotsError
      Given a PowerStore service on "controller"
      When I call Probe
      And I update volume cache
      And I call ListSnapshotsError <token>
      Then the error contains <errormsg>

      Examples:
      | token        | errormsg                        |
      | "not_uint32" | "Unable to parse StartingToken" |

@current
  Scenario Outline: Call ListSnapshots with StartToken error
	Given a PowerStore service on "controller"
	When I call Probe
	And I update volume cache
	And I call ListSnapshotsWithStartToken <token>
	Then the error contains <errormsg>

	Examples:
	| token        | errormsg                        |
    | "3"          | "> len(volumes)="               |

@current
    Scenario: Call ListSnapshots with Probe error
      Given a PowerStore service on "controller"
      And I rewrite PowerStore service option "Endpoint" ""
      When I call Probe
      And I reset PowerStore client
      And I call ListSnapshotsError ""
      Then the error contains "missing PowerStore API endpoint"

@current
  Scenario: Call ListSnapshots failure scenario
    Given a PowerStore service on "controller"
    When I call Probe
    And I call failure ListSnapshots
    Then the error contains "unable to list snapshots"

@current
    Scenario: Create volume from snapshot good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateVolumeFromSnapshot "16"
      Then a valid CreateVolumeResponse is returned

@current
    Scenario: Create volume from snapshot with incorrect size
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateVolumeFromSnapshotIncompatible "12"
      Then the error contains "rpc error: code = InvalidArgument desc = snapshot 39bb1b5f has incompatible size 16777216 bytes with requested 12582912 bytes"

@current
    Scenario: Create volume from snapshot and snapshot not found
      Given a PowerStore service on "controller"
      When I call Probe
      And I call CreateVolumeFromSnapshotError "16"
      Then the error contains "rpc error: code = NotFound desc = snapshot not found: 39bb1b5f"

@current
    Scenario: Create volume from snapshot failure scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call failure CreateVolumeFromSnapshot "16"
      Then the error contains "rpc error: code = Internal desc = can't create volume: 39bb1b5f"
