Feature: PowerStore CSI interface
    As a consumer of the CSI interface
    I want to test controller publish / unpublish interfaces
    So that they are known to work

@controllerPublish
@current
    Scenario: Call ControllerPublishVolume good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call PublishVolume with "single-writer" to "node1"
      Then a valid ControllerPublishVolumeResponse is returned

@controllerPublish
@current
    Scenario: Call ControllerPublishVolume with already mapped volume
      Given a PowerStore service on "controller"
      When I call Probe
      And I call PublishVolume with already mapped volume
      Then a valid ControllerPublishVolumeResponse is returned

@controllerPublish
@current
Scenario: Call ControllerNFSPublishVolume good scenario
  Given a PowerStore service on "controller"
  When I call Probe
  And I call PublishNFSVolume with "multiple-writer" to "csi-node-test-127.0.0.1"
  Then a valid ControllerPublishVolumeResponse is returned

@controllerPublish
@current
    Scenario: Call ControllerUnpublishVolume good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call UnpublishVolume from "node1"
      Then a valid ControllerUnpublishVolumeResponse is returned

@controllerPublish
@current
    Scenario: Call ControllerUnpublishVolume with not found host
      Given a PowerStore service on "controller"
      When I call Probe
      And I call UnpublishVolume with not found host
      Then the error contains "not found"

@controllerPublish
@current
    Scenario: Call ControllerNFSUnpublishVolume good scenario
      Given a PowerStore service on "controller"
      When I call Probe
      And I call UnpublishNFSVolume from "node1"
      Then a valid ControllerUnpublishVolumeResponse is returned